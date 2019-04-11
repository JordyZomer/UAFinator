# UAFinator
Mock up of UAF analysis through symbolic execution. 

By hooking on every free we can get the address from the rdi register.
When keeping track of those we have a callback on every memory (read|write) that checks if this region has been freed before.

-- Happy Hacking

# Todo

- Check if the memory has been allocated again with a hook to allocation functions
- Universal UAF detection
- Check for double frees too
