package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	reportLen = 90
	bufLen    = reportLen + 1

	hidiocSFeature = (3 << 30) | (bufLen << 16) | ('H' << 8) | 0x06
	hidiocGFeature = (3 << 30) | (bufLen << 16) | ('H' << 8) | 0x07

	classPower  = 0x07
	cmdBattery  = 0x80
	cmdCharging = 0x84
)

var transactionIDs = []byte{0x1f, 0x3f, 0xff, 0x08, 0x9f}

func buildReport(tid, class, cmd, size byte) [bufLen]byte {
	var b [bufLen]byte
	r := b[1:]
	r[1] = tid
	r[5] = size
	r[6] = class
	r[7] = cmd
	var crc byte
	for i := 2; i < 88; i++ {
		crc ^= r[i]
	}
	r[88] = crc
	return b
}

func ioctl(fd uintptr, req uintptr, buf *[bufLen]byte) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL, fd, req,
		uintptr(unsafe.Pointer(buf)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func query(f *os.File, tid, class, cmd, size byte) ([]byte, error) {
	req := buildReport(tid, class, cmd, size)
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if err := ioctl(f.Fd(), hidiocSFeature, &req); err != nil {
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)

		var resp [bufLen]byte
		if err := ioctl(f.Fd(), hidiocGFeature, &resp); err != nil {
			return nil, err
		}
		r := resp[1:]
		if r[6] != class || r[7] != cmd {
			lastErr = fmt.Errorf("mismatched response")
			continue
		}
		switch r[0] {
		case 0x02:
			return r, nil
		case 0x01:
			lastErr = fmt.Errorf("busy")
			time.Sleep(100 * time.Millisecond)
			continue
		case 0x04:
			return nil, fmt.Errorf("timeout (mouse asleep?)")
		case 0x05:
			return nil, fmt.Errorf("not supported")
		default:
			return nil, fmt.Errorf("status 0x%02x", r[0])
		}
	}
	return nil, lastErr
}

func razerHidraws() []string {
	var out []string
	matches, _ := filepath.Glob("/sys/class/hidraw/hidraw*/device/uevent")
	for _, p := range matches {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "HID_ID=") &&
				strings.Contains(line, ":00001532:") {

				name := filepath.Base(filepath.Dir(filepath.Dir(p)))
				out = append(out, "/dev/"+name)
			}
		}
	}
	return out
}

func main() {
	for _, dev := range razerHidraws() {
		f, err := os.OpenFile(dev, os.O_RDWR, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", dev, err)
			continue
		}
		for _, tid := range transactionIDs {
			bat, err := query(f, tid, classPower, cmdBattery, 0x02)
			if err != nil {
				continue
			}
			pct := int(bat[9]) * 100 / 255
			charging := false

			chg, err := query(f, tid, classPower, cmdCharging, 0x02)
			if err == nil {
				charging = chg[9] != 0
			}

			fmt.Printf(
				"%s tid=0x%02x battery=%d%% charging=%v\n",
				dev, tid, pct, charging,
			)
			f.Close()
			return
		}
		f.Close()
	}
	fmt.Fprintln(os.Stderr, "no Razer device answered")
	os.Exit(1)
}
