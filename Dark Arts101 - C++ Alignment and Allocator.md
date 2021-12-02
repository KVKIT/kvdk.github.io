# Welcome to Dark Arts 101 - C++ Alignment and Allocator

## TL;DR
1. Use `aligned_alloc` for vector types such as `__m256i`. Or use C++17.
2. Use `aligned_alloc` for over-aligned types specified with `alignas`. Or use C++17.
3. Never use `malloc`, `::operator new(size_t)` to dynamically allocate space for over-aligned types.

## 1. Introduction
Alignment of objects is important in C++. Compilers align basic types and user-defined types to meet requirements of hardware and improve performance.

However, some types may "over-align" than 8-byte or 16-byte boundary, which may cause error when used together with `::operator new` or STL containers.

Before C++17, a common mistake for beginner programmers is to use vector types such as `__m256i` introduced by SIMD instructions together with STL containers that dynamically allocate space, such as `std::vector`. Luckily, with the introduction of C++17, it is no longer the case.

Another less common mistake is to use over-aligned types together with STL constainers that have dynamic storage, or use `malloc` or `::operator new` to allocate space for them. An over-aligned type is a type with alignment stricter than 8 or 16 bytes, dependent on platform and compiler.

Now let us go all the way down the rabbit hole, to see what actually happens when we mix over-aligned types(including vector types) and allocation functions like `malloc` and `::operator new`.

## 2. Specifier `alignas` and `alignof`
Since C++11, user can use `alignas` specifier to specify the alignment of an expression or a user-defined type.

C++11 also supplies `alignof` operator to check the actual alignment of an expression or type. Note that the actual address of an expression may have a more aligned address due to runtime memory allocation. Programmer should rely on `alignof` operator instead of checking memory address manually.

### Syntax
```C++
alignas(type-id)
alignas(expression)

alignof(type-id)
alignof(expression) // Non-standard. Works on some compilers
```

### Example
```C++
#include <iostream>
#include <iomanip>

struct alignas(64) Aligned64        // alignas(type-id)
{
    char c;
};

Aligned64 a64;                      // alignas(expression)
alignas(1024) double d;             // alignas(expression)

int main()
{
    alignas(128) Aligned64 a128{};  // alignas(expression)
    // alignas(32) Aligned64 a32;   // Ill-formed, don't do this.

    std::cout 
        << alignof(decltype(a64)) << "\t"
        << alignof(a64) << "\t"
        << std::hex << &a64 << std::dec << "\n"
        
        << alignof(decltype(d)) << "\t"
        << alignof(d) << "\t"
        << std::hex << &d << std::dec << "\n"

        << alignof(decltype(a128)) << "\t"
        << alignof(a128) << "\t"
        << std::hex << &a128 << std::dec << "\n"

        << std::endl;

    return 0;
}
```
### Possible Output
```
64      64      0x5645d45f9840
8       1024    0x5645d45f9800
64      128     0x7fff951d4f80
```
### Explanation
`Aligned64` is an "over-aligned" type. Compiler generates code to properly allocate space at static memory or stack for `Aligned64` objects. Note that the actual address may be "more-aligned" than requirement. 

## 3. Dynamic Memory Allocation and `std::max_align_t`
The problem with "over-aligned" types is that, compiler can only properly align them during compilation and linking phase. User must pay close attention when dynamically allocate space with objects of alignment more than 8 bytes or 16 bytes depending on platform.

Some C++11 implementations offers type definition `std::max_align_t`, and guarantees that space allocated by `malloc` is aligned at least as strict as `alignof(std::max_align_t)`.

### Example
```C++
#include <cstddef>

#include <iostream>

int main()
{
    std::cout << alignof(std::max_align_t) << std::endl;
}
```
### Possible Output
```
16
```
That being said, space allocated by `malloc` and `::operator new` may not satisfy the alignment requirement of user defined class specified with alignment stricter than `alignof(std::max_align_t)`.
### Example
```C++
#include <cstddef>

#include <iostream>
#include <iomanip>

struct alignas(64) Aligned64
{
    char c;
};

int main()
{
    Aligned64* a64_ptr = new Aligned64;

    Aligned64* a64_ptr2 = static_cast<Aligned64*>(malloc(sizeof(Aligned64)));

    std::cout 
        << alignof(*a64_ptr) << "\t"
        << std::hex << a64_ptr << std::dec << "\n"
        
        << alignof(*a64_ptr2) << "\t"
        << std::hex << a64_ptr2 << std::dec << "\n"
        
        << std::endl;

    delete a64_ptr;
    free(a64_ptr2);

    return 0;
}
```
### Possible Output
```
64      0x55d60e855ec0
64      0x55d60e855e70
```
### Explanation
Default C++ `::operator new` and `malloc` are not alignment-sensitive. Actual alignment on heap does not meet requirement of user-defined type. Sometimes allocated space do meet alignment requirement. Sometimes it does NOT.

## 4. Another Ill-formed Example
Intel offers SIMD(Single Intruction Multiple Data) for high performance computing. For example, instruction set `AVX2` has packed data types such as `__m256i`(8-packed integers) and `__m256d`(4-packed double-precision floats). Operations on such types usually require the data to be properly aligned. For `__m256i` and `__m256d` in this example, these types are required to be 32-byte aligned. If an object of `__m256i` is not properly aligned, instructions on it may trigger a segment fault.
### Example
```C++
#include <iostream>
#include <iomanip>
#include <vector>

#include <immintrin.h>

int main()
{
    __m256i data{};                  // Okay, aligned on stack.
    std::vector<__m256i> vec(16);    // Alignment not guaranteed!

    std::cout 
        << alignof(data) << "\t"
        << std::hex << &data << std::dec << "\n"
        
        << alignof(vec[0]) << "\t"
        << std::hex << vec.data() << std::dec << "\n"
        
        << std::endl;

    return 0;
}

```
### Possible Output (C++17)
```
32      0x7ffc292414e0
32      0x558e69d8fea0
```
### Another Possible Output (C++11 or C++14)
```
[1]    102849 segmentation fault  ./test_align
```
### Explanation
Since GCC 7 with `-std=c++17` support, default allocator in STL containers do support proper alignment for user-defined types. However, before C++17, STL containers are not aware of alignment specified by `alignas` specifier.

If we disassembles the code compiled with `g++-11 -std=c++11 -O2 -mavx2`, we can see the following code snippet in `main` funtion.

(Note: dual to the difference between machines and environment, the segment fault may not be triggered everytime for every build. You may have to try different GCC versions and different optimization parameters to generate different code that may trigger this segfault.)

```asm
0000000000000b80 <main>:
 b80:	55                   	push   %rbp
 b81:	c5 f9 ef c0          	vpxor  %xmm0,%xmm0,%xmm0    # zeroing %xmm0, also %ymm0
 b85:	bf 00 02 00 00       	mov    $0x200,%edi          # 512(B) = 16 * 32(B)
 b8a:	48 89 e5             	mov    %rsp,%rbp
 b8d:	41 56                	push   %r14
 b8f:	41 55                	push   %r13
 b91:	41 54                	push   %r12
 b93:	48 83 e4 e0          	and    $0xffffffffffffffe0,%rsp
 b97:	48 83 ec 40          	sub    $0x40,%rsp
 b9b:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax        # stack-guard
 ba2:	00 00 
 ba4:	48 89 44 24 38       	mov    %rax,0x38(%rsp)
 ba9:	31 c0                	xor    %eax,%eax
 bab:	c5 fd 7f 04 24       	vmovdqa %ymm0,(%rsp)        # zeroing [%rsp,%rsp+32]
 bb0:	c5 f8 77             	vzeroupper 
 bb3:	e8 38 ff ff ff       	callq  af0 <_Znwm@plt>      # Call ::operator new with parameter %rdi = 512
 bb8:	c5 f9 ef c0          	vpxor  %xmm0,%xmm0,%xmm0    # zeroing %xmm0, also %ymm0
 bbc:	49 89 c4             	mov    %rax,%r12
 bbf:	c5 fd 7f 00          	vmovdqa %ymm0,(%rax)        # Set vec[0] to zeros, may trigger segfault
 bc3:	48 83 c0 20          	add    $0x20,%rax
 bc7:	49 8d 94 24 00 02 00 	lea    0x200(%r12),%rdx
 bce:	00 
 bcf:	48 39 d0             	cmp    %rdx,%rax
 bd2:	75 12                	jne    be6 <main+0x66>
 bd4:	eb 1d                	jmp    bf3 <main+0x73>
```
Instruction `vmovdqa` stores 256-bits of interger data to memory. It requires the destination to be aligned to 32-byte boundary, otherwise it may trigger an exception, which is then captured by system and generates segfault in this example.

### Note
Different compilers generate different optimized code for `memset`. For example, we observe GCC 8.4.0 using `vmovdqa` to zero-fill space allocated by `malloc` for an array of object specified with `alignas(64)`, and then triggers a segfault.

## 5. Solutions Compliant to C++ Standard
### 5.1. Use C++ 17
C++17 specifies that `std::allocator<T>::allocate(size_t)` will allocate uninitialized space with `::operator new(size_t, std::align_val_t)`, which means that STL containers such as `std::vector<T>`, with `std::allocator<T>` as default allocator, will respect over-alignment requirements specified by user. You can simply use `std::vector<__m256i>` without worrying about segfault triggered by `vmovdqa`.

### 5.2. C funtion `aligned_alloc`
Since C11, standard library offers `void* aligned_alloc(size_t align, size_t n)` to allocate `n` bytes aligned to boundary specified by parameter `align`.

`aligned_alloc` works similar to `malloc` and space allocated by it must be freed by calling `free()`.

### Example: AlignedAllocator for STL Containers
```C++
#include <iostream>
#include <iomanip>
#include <vector>

#include <immintrin.h>

template <typename T> class AlignedAllocator {
public:
  using value_type = T;

  inline T *allocate(size_t n) {
    T *p = static_cast<T *>(aligned_alloc(alignof(T), n * sizeof(T)));
    if (p == nullptr) {
      throw std::bad_alloc{};
    }
    return p;
  }

  inline void deallocate(T *p, size_t) noexcept { free(p); }
};

int main()
{
    __m256i data{};
    std::vector<__m256i, AlignedAllocator<__m256i>> vec(16);

    std::cout 
        << alignof(data) << "\t"
        << std::hex << &data << std::dec << "\n"
        
        << alignof(vec[0]) << "\t"
        << std::hex << vec.data() << std::dec << "\n"
        
        << std::endl;

    return 0;
}
```
User may also use `aligned_alloc` to overload `operator new`, `operator delete` for classes with specific alignment requirements.

## 6. Conclusion
1. Use `aligned_alloc` for vector types such as `__m256i`. Or use C++17.
2. Use `aligned_alloc` for over-aligned types specified with `alignas`. Or use C++17.
3. Never use `malloc`, `::operator new(size_t)` to dynamically allocate space for over-aligned types.



