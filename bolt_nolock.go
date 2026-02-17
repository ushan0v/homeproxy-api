package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"os"
	"sort"
	"syscall"
)

const (
	// bbolt file format constants (little-endian, matches linux/mipsle).
	boltMagic   uint32 = 0xED0CDAED
	boltVersion uint32 = 2

	// Page flags.
	branchPageFlag uint16 = 0x01
	leafPageFlag   uint16 = 0x02
	metaPageFlag   uint16 = 0x04

	// Leaf element flags.
	bucketLeafFlag uint32 = 0x01

	pageHeaderSize   = 16
	metaSize         = 64
	bucketHeaderSize = 16
	branchElemSize   = 16
	leafElemSize     = 16
)

var (
	errInvalidDB = errors.New("invalid bbolt db")
	errNotFound  = errors.New("not found")
)

type boltMeta struct {
	magic    uint32
	version  uint32
	pageSize uint32
	flags    uint32

	rootPgid uint64
	rootSeq  uint64

	freelist uint64
	pgid     uint64
	txid     uint64
	checksum uint64
}

func parseMetaAt(data []byte, offset int) (boltMeta, error) {
	if offset < 0 || offset+pageHeaderSize+metaSize > len(data) {
		return boltMeta{}, errInvalidDB
	}

	// Validate this is a meta page.
	flags := binary.LittleEndian.Uint16(data[offset+8:])
	if flags != metaPageFlag {
		return boltMeta{}, errInvalidDB
	}

	moff := offset + pageHeaderSize
	m := boltMeta{
		magic:    binary.LittleEndian.Uint32(data[moff:]),
		version:  binary.LittleEndian.Uint32(data[moff+4:]),
		pageSize: binary.LittleEndian.Uint32(data[moff+8:]),
		flags:    binary.LittleEndian.Uint32(data[moff+12:]),
		rootPgid: binary.LittleEndian.Uint64(data[moff+16:]),
		rootSeq:  binary.LittleEndian.Uint64(data[moff+24:]),
		freelist: binary.LittleEndian.Uint64(data[moff+32:]),
		pgid:     binary.LittleEndian.Uint64(data[moff+40:]),
		txid:     binary.LittleEndian.Uint64(data[moff+48:]),
		checksum: binary.LittleEndian.Uint64(data[moff+56:]),
	}
	if m.magic != boltMagic || m.version != boltVersion {
		return boltMeta{}, errInvalidDB
	}
	if m.pageSize == 0 || m.pageSize&(m.pageSize-1) != 0 || m.pageSize < 1024 || m.pageSize > 1<<20 {
		return boltMeta{}, errInvalidDB
	}

	h := fnv.New64a()
	_, _ = h.Write(data[moff : moff+56])
	if h.Sum64() != m.checksum {
		return boltMeta{}, errInvalidDB
	}
	return m, nil
}

type boltPageHeader struct {
	id       uint64
	flags    uint16
	count    uint16
	overflow uint32
}

type boltReader struct {
	f        *os.File
	data     []byte
	pageSize int
	meta     boltMeta
}

func openBoltNoLock(path string) (*boltReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Size() < 2*4096 {
		_ = f.Close()
		return nil, errInvalidDB
	}

	mm, err := syscall.Mmap(int(f.Fd()), 0, int(st.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	// Parse meta0 first (offset 0).
	meta0, err0 := parseMetaAt(mm, 0)
	var meta1 boltMeta
	var err1 error
	if err0 == nil {
		meta1, err1 = parseMetaAt(mm, int(meta0.pageSize))
	} else {
		// Fallback to the most common page size.
		meta1, err1 = parseMetaAt(mm, 4096)
	}

	var chosen boltMeta
	switch {
	case err0 == nil && err1 == nil:
		if meta1.txid > meta0.txid {
			chosen = meta1
		} else {
			chosen = meta0
		}
	case err0 == nil:
		chosen = meta0
	case err1 == nil:
		chosen = meta1
	default:
		_ = syscall.Munmap(mm)
		_ = f.Close()
		return nil, errInvalidDB
	}

	r := &boltReader{
		f:        f,
		data:     mm,
		pageSize: int(chosen.pageSize),
		meta:     chosen,
	}
	return r, nil
}

func (r *boltReader) Close() {
	if r == nil {
		return
	}
	if r.data != nil {
		_ = syscall.Munmap(r.data)
	}
	if r.f != nil {
		_ = r.f.Close()
	}
}

func (r *boltReader) readPageAt(pgid uint64) (boltPageHeader, []byte, error) {
	off := int(pgid) * r.pageSize
	if off < 0 || off+pageHeaderSize > len(r.data) {
		return boltPageHeader{}, nil, errInvalidDB
	}
	h := boltPageHeader{
		id:       binary.LittleEndian.Uint64(r.data[off:]),
		flags:    binary.LittleEndian.Uint16(r.data[off+8:]),
		count:    binary.LittleEndian.Uint16(r.data[off+10:]),
		overflow: binary.LittleEndian.Uint32(r.data[off+12:]),
	}
	span := int(h.overflow+1) * r.pageSize
	if span <= 0 || off+span > len(r.data) {
		return boltPageHeader{}, nil, errInvalidDB
	}
	return h, r.data[off : off+span], nil
}

func readLeafElem(page []byte, idx int) (flags uint32, key []byte, value []byte, ok bool) {
	base := pageHeaderSize + idx*leafElemSize
	if base < 0 || base+leafElemSize > len(page) {
		return 0, nil, nil, false
	}
	flags = binary.LittleEndian.Uint32(page[base:])
	// Note: bbolt stores pos as an offset relative to the element struct address.
	pos := int(binary.LittleEndian.Uint32(page[base+4:]))
	ksz := int(binary.LittleEndian.Uint32(page[base+8:]))
	vsz := int(binary.LittleEndian.Uint32(page[base+12:]))
	if pos < 0 || ksz < 0 || vsz < 0 {
		return 0, nil, nil, false
	}
	keyStart := base + pos
	keyEnd := keyStart + ksz
	valStart := keyEnd
	valEnd := valStart + vsz
	if keyStart < 0 || valEnd < 0 || keyStart > len(page) || valEnd > len(page) {
		return 0, nil, nil, false
	}
	key = page[keyStart:keyEnd]
	value = page[valStart:valEnd]
	return flags, key, value, true
}

func readBranchElem(page []byte, idx int) (key []byte, pgid uint64, ok bool) {
	base := pageHeaderSize + idx*branchElemSize
	if base < 0 || base+branchElemSize > len(page) {
		return nil, 0, false
	}
	// Note: bbolt stores pos as an offset relative to the element struct address.
	pos := int(binary.LittleEndian.Uint32(page[base:]))
	ksz := int(binary.LittleEndian.Uint32(page[base+4:]))
	pgid = binary.LittleEndian.Uint64(page[base+8:])
	if pos < 0 || ksz < 0 {
		return nil, 0, false
	}
	keyStart := base + pos
	keyEnd := keyStart + ksz
	if keyStart < 0 || keyEnd < 0 || keyStart > len(page) || keyEnd > len(page) {
		return nil, 0, false
	}
	key = page[keyStart:keyEnd]
	return key, pgid, true
}

func (r *boltReader) descendToLeaf(rootPgid uint64, searchKey []byte) ([]byte, error) {
	pgid := rootPgid
	for {
		h, page, err := r.readPageAt(pgid)
		if err != nil {
			return nil, err
		}
		switch h.flags {
		case leafPageFlag:
			return page, nil
		case branchPageFlag:
			if h.count == 0 {
				return nil, errInvalidDB
			}
			// Find the last child whose key <= searchKey.
			count := int(h.count)
			index := sort.Search(count, func(i int) bool {
				k, _, ok := readBranchElem(page, i)
				if !ok {
					return true
				}
				return bytes.Compare(k, searchKey) >= 0
			})
			if index >= count {
				index = count - 1
			} else {
				k, _, ok := readBranchElem(page, index)
				if ok && !bytes.Equal(k, searchKey) && index > 0 {
					index--
				}
			}
			_, child, ok := readBranchElem(page, index)
			if !ok {
				return nil, errInvalidDB
			}
			pgid = child
		default:
			return nil, errInvalidDB
		}
	}
}

func findInTreeLeaf(page []byte, searchKey []byte) (flags uint32, value []byte, err error) {
	// Binary search on leaf elements.
	// Keys are sorted lexicographically.
	// Returns errNotFound if not found.
	hCount := int(binary.LittleEndian.Uint16(page[10:]))
	index := sort.Search(hCount, func(i int) bool {
		_, k, _, ok := readLeafElem(page, i)
		if !ok {
			return true
		}
		return bytes.Compare(k, searchKey) >= 0
	})
	if index >= hCount {
		return 0, nil, errNotFound
	}
	f, k, v, ok := readLeafElem(page, index)
	if !ok {
		return 0, nil, errInvalidDB
	}
	if !bytes.Equal(k, searchKey) {
		return 0, nil, errNotFound
	}
	return f, v, nil
}

func (r *boltReader) getBucketRoot(name string) (rootPgid uint64, inlinePage []byte, err error) {
	root := r.meta.rootPgid
	leaf, err := r.descendToLeaf(root, []byte(name))
	if err != nil {
		return 0, nil, err
	}
	flags, v, err := findInTreeLeaf(leaf, []byte(name))
	if err != nil {
		return 0, nil, err
	}
	if flags&bucketLeafFlag == 0 {
		return 0, nil, errInvalidDB
	}
	if len(v) < bucketHeaderSize {
		return 0, nil, errInvalidDB
	}
	rootPgid = binary.LittleEndian.Uint64(v[0:])
	// sequence := binary.LittleEndian.Uint64(v[8:])
	if rootPgid == 0 {
		inlinePage = v[bucketHeaderSize:]
	}
	return rootPgid, inlinePage, nil
}

func walkInlinePage(page []byte, visit func(k, v []byte) error) error {
	if len(page) < pageHeaderSize {
		return errInvalidDB
	}
	flags := binary.LittleEndian.Uint16(page[8:])
	count := int(binary.LittleEndian.Uint16(page[10:]))
	switch flags {
	case leafPageFlag:
		for i := 0; i < count; i++ {
			elemFlags, k, v, ok := readLeafElem(page, i)
			if !ok {
				return errInvalidDB
			}
			if elemFlags&bucketLeafFlag != 0 {
				continue
			}
			if err := visit(k, v); err != nil {
				return err
			}
		}
		return nil
	case branchPageFlag:
		// Inline branch buckets are unlikely here; keep minimal support by refusing.
		return errInvalidDB
	default:
		return errInvalidDB
	}
}

func (r *boltReader) walkPages(pgid uint64, visit func(k, v []byte) error) error {
	h, page, err := r.readPageAt(pgid)
	if err != nil {
		return err
	}
	switch h.flags {
	case leafPageFlag:
		for i := 0; i < int(h.count); i++ {
			elemFlags, k, v, ok := readLeafElem(page, i)
			if !ok {
				return errInvalidDB
			}
			if elemFlags&bucketLeafFlag != 0 {
				continue
			}
			if err := visit(k, v); err != nil {
				return err
			}
		}
		return nil
	case branchPageFlag:
		for i := 0; i < int(h.count); i++ {
			_, child, ok := readBranchElem(page, i)
			if !ok {
				return errInvalidDB
			}
			if err := r.walkPages(child, visit); err != nil {
				return err
			}
		}
		return nil
	default:
		return errInvalidDB
	}
}

func (r *boltReader) forEachRuleSetKV(fn func(k string, v []byte) error) error {
	rootPgid, inline, err := r.getBucketRoot("rule_set")
	if err != nil {
		return err
	}
	if rootPgid == 0 {
		return walkInlinePage(inline, func(k, v []byte) error {
			return fn(string(k), v)
		})
	}
	return r.walkPages(rootPgid, func(k, v []byte) error {
		return fn(string(k), v)
	})
}
