section .text
    global main

main:
    ; Perform the calculation: 2 + (4 * 3) - 6
    mov rax, 4        ; rax = 4
    imul rax, 3       ; rax = 4 * 3
    add rax, 2        ; rax = 4 * 3 + 2
    sub rax, 6        ; rax = (4 * 3 + 2) - 6

    ; Return the result as the exit code
    ret

