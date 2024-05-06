oh no, my device starts shredding everything I put in it...
```bash
qemu-system-arm -cpu cortex-m3 -machine lm3s6965evb -kernel arxelerated -semihosting -semihosting-config enable=on,target=native -serial mon:stdio
```