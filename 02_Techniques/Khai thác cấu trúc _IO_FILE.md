Kỹ thuật khai thác cấu trúc `FILE` (còn được gọi là FSOP - File Stream Oriented Programming) là một phương pháp phổ biến nhằm chiếm quyền điều khiển luồng thực thi của chương trình (control-flow hijacking). Kẻ tấn công (attacker) có thể ghi đè lên một con trỏ `FILE` nằm trên heap để trỏ nó đến một cấu trúc giả mạo. Bằng cách lợi dụng một con trỏ có tên là `vtable` bên trong cấu trúc này, kẻ tấn công có thể thực thi mã tùy ý.

Chúng ta biết rằng cấu trúc `FILE` được sử dụng bởi một loạt các hàm thao tác với stream (luồng dữ liệu) như `fopen()`, `fread()`, `fclose()`. Hầu hết các cấu trúc `FILE` đều được lưu trữ trên heap (ngoại trừ `stdin`, `stdout`, `stderr` nằm trong vùng dữ liệu của libc). Con trỏ đến các cấu trúc này được tạo động và trả về bởi hàm `fopen()`.

Trong thư viện glibc (ví dụ phiên bản 2.23), cấu trúc này thực chất là `_IO_FILE_plus`, bao gồm một cấu trúc `_IO_FILE` và một con trỏ đến cấu trúc `_IO_jump_t`.

``` c
// libio/libioP.h

struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};

/* We always allocate an extra word following an _IO_FILE.
   This contains a pointer to the function jump table used.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */

struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};

extern struct _IO_FILE_plus *_IO_list_all;
```

Con trỏ `vtable` thực chất trỏ đến một "bảng nhảy" chứa các con trỏ hàm, đây là một cơ chế được triển khai để tương thích với virtual function (hàm ảo) của C++. Khi chương trình thực hiện một thao tác trên stream, nó sẽ gọi đến một hàm tương ứng nằm trong bảng nhảy này.
``` c
// libio/libio.h

struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /* char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
#if defined _G_IO_IO_FILE_VERSION && _G_IO_IO_FILE_VERSION == 0x20001
  _IO_off64_t _offset;
# if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
# else
  void *__pad1;
  void *__pad2;
  void *__pad3;
  void *__pad4;
# endif
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
#endif
};

extern struct _IO_FILE_plus _IO_2_1_stdin_;
extern struct _IO_FILE_plus _IO_2_1_stdout_;
extern struct _IO_FILE_plus _IO_2_1_stderr_;
```

Các cấu trúc `FILE` trong một tiến trình được liên kết với nhau thành một danh sách liên kết (linked list) thông qua trường `_chain`. Con trỏ đầu của danh sách này là biến toàn cục `_IO_list_all`.
Ngoài ra, cấu trúc `_IO_wide_data` cũng là một thành phần cần chú ý cho các kỹ thuật về sau:
``` C
/* Extra data for wide character streams.  */
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;

  wchar_t _shortbuf[1];

  const struct _IO_jump_t *_wide_vtable;
};
```
### Phân tích mã nguồn các hàm I/O

Bây giờ, chúng ta sẽ xem xét cách triển khai của một vài hàm I/O quan trọng trong `glibc`.

---
### `fopen`

Khi một file được mở, hàm `_IO_new_fopen` (hoặc `fopen`) sẽ gọi hàm nội bộ `__fopen_internal`.

```C
// libio/iofopen.c

_IO_FILE *
__fopen_internal (const char *filename, const char *mode, int is32)
{
  struct locked_FILE
  {
    struct _IO_FILE_plus fp;
#ifdef _IO_MTSAFE_IO
    _IO_lock_t lock;
#endif
    struct _IO_wide_data wd;
  } *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));   // Cấp phát bộ nhớ cho cấu trúc FILE

  if (new_f == NULL)
    return NULL;
#ifdef _IO_MTSAFE_IO
  new_f->fp.file._lock = &new_f->lock;
#endif
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  _IO_no_init (&new_f->fp.file, 0, 0, &new_f->wd, &_IO_wfile_jumps);
#else
  _IO_no_init (&new_f->fp.file, 1, 0, NULL, NULL);
#endif
  _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;                                 // Thiết lập vtable trỏ đến &_IO_file_jumps
  _IO_file_init (&new_f->fp);                                               // Gọi hàm _IO_file_init để khởi tạo
#if  !_IO_UNIFIED_JUMPTABLES
  new_f->fp.vtable = NULL;
#endif
  if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)    // Mở file đích
    return __fopen_maybe_mmap (&new_f->fp.file);

  _IO_un_link (&new_f->fp);
  free (new_f);
  return NULL;
}

_IO_FILE *
_IO_new_fopen (const char *filename, const char *mode)
{
  return __fopen_internal (filename, mode, 1);
}
```

Hàm `_IO_file_init` sau đó sẽ gọi `_IO_link_in` để chèn cấu trúc `FILE` vừa được tạo vào danh sách liên kết.

```C
// libio/fileops.c

# define _IO_new_file_init _IO_file_init

void
_IO_new_file_init (struct _IO_FILE_plus *fp)
{
  /* POSIX.1 allows another file handle to be used to change the position
     of our file descriptor.  Hence we actually don't know the actual
     position before we do the first fseek (and until a following fflush). */
  fp->file._offset = _IO_pos_BAD;
  fp->file._IO_file_flags |= CLOSED_FILEBUF_FLAGS;

  _IO_link_in (fp);         // Gọi _IO_link_in để thêm fp vào danh sách liên kết
  fp->file._fileno = -1;
}
```

Hàm `_IO_link_in` thực hiện việc thêm cấu trúc `FILE` mới vào đầu danh sách liên kết toàn cục `_IO_list_all`.

```C
// libio/genops.c

void
_IO_link_in (struct _IO_FILE_plus *fp)
{
  if ((fp->file._flags & _IO_LINKED) == 0)
    {
      fp->file._flags |= _IO_LINKED;
#ifdef _IO_MTSAFE_IO
      _IO_cleanup_region_start_noarg (flush_cleanup);
      _IO_lock_lock (list_all_lock);
      run_fp = (_IO_FILE *) fp;
      _IO_flockfile ((_IO_FILE *) fp);
#endif
      fp->file._chain = (_IO_FILE *) _IO_list_all;  // Nối fp vào đầu danh sách
      _IO_list_all = fp;                            // Cập nhật con trỏ đầu danh sách _IO_list_all để trỏ tới fp
      ++_IO_list_all_stamp;
#ifdef _IO_MTSAFE_IO
      _IO_funlockfile ((_IO_FILE *) fp);
      run_fp = NULL;
      _IO_lock_unlock (list_all_lock);
      _IO_cleanup_region_end (0);
#endif
    }
}
```

---
### `fread`
Hàm `_IO_fread` sẽ gọi `_IO_sgetn` để thực hiện việc đọc dữ liệu.

``` C
// libio/iofread.c

_IO_size_t
_IO_fread (void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t bytes_requested = size * count;
  _IO_size_t bytes_read;
  CHECK_FILE (fp, 0);
  if (bytes_requested == 0)
    return 0;
  _IO_acquire_lock (fp);
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);   // Gọi hàm _IO_sgetn
  _IO_release_lock (fp);
  return bytes_requested == bytes_read ? count : bytes_read / size;
}
```

`_IO_sgetn` lại tiếp tục gọi macro `_IO_XSGETN`.

```C
// libio/genops.c

_IO_size_t
_IO_sgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
  /* FIXME handle putback buffer here! */
  return _IO_XSGETN (fp, data, n);          // Gọi macro _IO_XSGETN
}
```

Macro này được định nghĩa để thực hiện một lệnh gọi gián tiếp thông qua `vtable`.
``` C
// libio/libioP.h

#define _IO_JUMPS_FILE_plus(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE_plus, vtable)

#if _IO_JUMPS_OFFSET
# define _IO_JUMPS_FUNC(THIS) \
 (*(struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (THIS) \
			   + (THIS)->_vtable_offset))
# define _IO_vtable_offset(THIS) (THIS)->_vtable_offset
#else
# define _IO_JUMPS_FUNC(THIS) _IO_JUMPS_FILE_plus (THIS)
# define _IO_vtable_offset(THIS) 0
#endif

#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)

#define _IO_XSGETN(FP, DATA, N) JUMP2 (__xsgetn, FP, DATA, N)
```

Như vậy, macro `_IO_XSGETN` cuối cùng sẽ gọi đến hàm `__xsgetn` nằm trong `vtable`, cụ thể là:

```C
// libio/fileops.c

_IO_size_t
_IO_file_xsgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
...
}
```

---
### `fwrite`

Tương tự `fread`, hàm `_IO_fwrite` gọi `_IO_sputn` để thực hiện ghi dữ liệu.

``` C
// libio/iofwrite.c

_IO_size_t
_IO_fwrite (const void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t request = size * count;
  _IO_size_t written = 0;
  CHECK_FILE (fp, 0);
  if (request == 0)
    return 0;
  _IO_acquire_lock (fp);
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request);      // Gọi hàm _IO_sputn
  _IO_release_lock (fp);
  /* ... */
  if (written == request || written == EOF)
    return count;
  else
    return written / size;
}
```

`_IO_sputn` là một macro trỏ đến `_IO_XSPUTN`, và cũng thực hiện một lệnh gọi hàm gián tiếp thông qua `vtable`.

``` C
// libio/libioP.h

#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)

#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
```

Macro `_IO_XSPUTN` cuối cùng sẽ gọi đến hàm sau:

``` C
// libio/fileops.c

_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
...
}
```

---
### `fclose`

Khi `fclose` được gọi, nó sẽ thực hiện hai thao tác chính: gỡ bỏ cấu trúc `FILE` ra khỏi danh sách liên kết và giải phóng bộ nhớ đã cấp phát cho nó.
```C
// libio/iofclose.c

int
_IO_new_fclose (_IO_FILE *fp)
{
  int status;

  CHECK_FILE(fp, EOF);
  /* ... */

  /* First unlink the stream.  */
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);  // Gỡ fp ra khỏi danh sách liên kết

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);            // Đóng file đích
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp);
  
  /* ... */
  
  if (fp != _IO_stdin && fp != _IO_stdout && fp != _IO_stderr)
    {
      fp->_IO_file_flags = 0;
      free(fp);                                 // Giải phóng cấu trúc FILE
    }

  return status;
}
```
### FSOP (File Stream Oriented Programming)

**FSOP (File Stream Oriented Programming)** là một kỹ thuật khai thác nhắm vào việc chiếm quyền điều khiển (hijack) biến toàn cục `_IO_list_all` trong `libc.so` để tạo ra một danh sách liên kết giả mạo. Kỹ thuật này thường được kích hoạt thông qua việc gọi hàm `_IO_flush_all_lockp()`. Hàm này sẽ được gọi trong ba trường hợp chính:
1. Khi `libc` phát hiện lỗi liên quan đến bộ nhớ.
2. Khi chương trình thực thi hàm `exit()`.
3. Khi hàm `main` kết thúc và trả về.
Khi `glibc` phát hiện lỗi bộ nhớ, chuỗi hàm sau sẽ được gọi tuần tự: `malloc_printerr` -> `__libc_message` -> `__GI_abort` -> `_IO_flush_all_lockp` -> `_IO_OVERFLOW`.
``` C
// libio/genops.c

int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;

#ifdef _IO_MTSAFE_IO
  __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
  if (do_lock)
    _IO_lock_lock (list_all_lock);
#endif

  last_stamp = _IO_list_all_stamp;
  fp = (_IO_FILE *) _IO_list_all;   // Ghi đè con trỏ này để trỏ tới danh sách liên kết giả mạo
  while (fp != NULL)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)   // Điều kiện kiểm tra
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
#endif
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)     // fp trỏ đến một vtable giả mạo
	result = EOF;

      if (do_lock)
	_IO_funlockfile (fp);
      run_fp = NULL;

      if (last_stamp != _IO_list_all_stamp)
	{
	  /* Something was added to the list.  Start all over again.  */
	  fp = (_IO_FILE *) _IO_list_all;
	  last_stamp = _IO_list_all_stamp;
	}
      else
	fp = fp->_chain;    // Trỏ đến đối tượng _IO_FILE tiếp theo
    }
    
  // ...
  return result;
}
```

Macro `_IO_OVERFLOW` sẽ thực hiện một lệnh gọi gián tiếp thông qua `vtable`:
``` C
// libio/libioP.h

#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)
#define _IO_WOVERFLOW(FP, CH) WJUMP1 (__overflow, FP, CH)
```

Do đó, trong quá trình thực thi `_IO_OVERFLOW(fp, EOF)`, chương trình sẽ gọi đến hàm `__overflow` trong `vtable` giả mạo của chúng ta, và cuối cùng thực thi `system('/bin/sh')`.

Ngoài ra, còn một luồng tấn công FSOP khác khi đóng một stream:
``` C
// libio/iofclose.c

int
_IO_new_fclose (_IO_FILE *fp)
{
  // ...
  _IO_FINISH (fp);                      // fp trỏ đến một vtable giả mạo
  // ...
  if (fp != _IO_stdin && fp != _IO_stdout && fp != _IO_stderr)
    {
      fp->_IO_file_flags = 0;
      free(fp);
    }

  return status;
}
```

Tương tự, macro `_IO_FINISH` cũng gọi đến một hàm trong `vtable`:
``` C
// libio/libioP.h

#define _IO_FINISH(FP) JUMP1 (__finish, FP, 0)
#define _IO_WFINISH(FP) WJUMP1 (__finish, FP, 0)
```

Bằng cách này, quá trình thực thi `_IO_FINISH(fp)` cũng có thể được lợi dụng để gọi `system('/bin/sh')`.
### Cơ chế phòng thủ trong libc-2.24

Kể từ phiên bản `libc-2.24`, một cơ chế kiểm tra tính hợp lệ của con trỏ `vtable` đã được thêm vào để chống lại kỹ thuật tấn công trên. Thay đổi này giới thiệu hai hàm mới: `IO_validate_vtable` và `_IO_vtable_check`.
``` C
// libio/libioP.h

static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  const char *ptr = (const char *) vtable;
  uintptr_t offset = ptr - __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```

Cơ chế này hoạt động bằng cách đặt tất cả các `vtable` hợp lệ của `libio` vào một section (phân đoạn) bộ nhớ chuyên dụng và chỉ đọc có tên là `__libc_IO_vtables`. Trước khi thực hiện bất kỳ lệnh gọi gián tiếp nào, con trỏ `vtable` sẽ được kiểm tra xem nó có nằm trong vùng biên của section này hay không. Nếu con trỏ nằm ngoài phạm vi cho phép, hàm `_IO_vtable_check()` sẽ được gọi để kiểm tra sâu hơn và sẽ chấm dứt tiến trình nếu phát hiện bất thường.
### Kỹ thuật khai thác trên libc-2.24

#### Sử dụng `_IO_str_jumps`

Với cơ chế phòng thủ mới, kỹ thuật khai thác bằng cách trỏ `vtable` đến một vùng nhớ tùy ý đã không còn hiệu quả. Tuy nhiên, các kỹ thuật mới đã xuất hiện để vượt qua nó.

Vì không thể trỏ `vtable` ra ngoài vùng `__libc_IO_vtables`, hướng tiếp cận mới là tìm kiếm những `vtable` hữu ích ngay bên trong section này. Một trong số đó là `_IO_str_jumps`:
``` C
// libio/strops.c

const struct _IO_jump_t _IO_str_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_str_finish),
  JUMP_INIT(overflow, _IO_str_overflow),
  JUMP_INIT(underflow, _IO_str_underflow),
  // ...
};
```

`vtable` này chứa con trỏ đến hàm `_IO_str_overflow`, và hàm này có một điểm yếu có thể khai thác:

``` C
// libio/strops.c

int
_IO_str_overflow (_IO_FILE *fp, int c)
{
  // ...
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))  // Điều kiện #define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)
    {
      // ...
	  _IO_size_t new_size = 2 * old_blen + 100;    // `new_size` sẽ là đối số cho hàm được gọi
	  // ...
	  new_buf = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size); // Tại đây, ta kiểm soát được con trỏ hàm và đối số của nó.
                                                                                     // Mục tiêu: system(bin_sh_addr)
    // ...
}
```

Cấu trúc `_IO_strfile` được định nghĩa như sau:
``` C
// libio/strfile.h

struct _IO_str_fields
{
  _IO_alloc_type _allocate_buffer;
  _IO_free_type _free_buffer;
};

typedef struct _IO_strfile_
{
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;
} _IO_strfile;
```

Để khai thác, kẻ tấn công cần tạo một cấu trúc `FILE` giả mạo với các giá trị được tính toán cẩn thận để vượt qua các điều kiện kiểm tra và kiểm soát được con trỏ hàm `_allocate_buffer` cũng như đối số `new_size`. Cụ thể, `_allocate_buffer` sẽ được trỏ đến địa chỉ của hàm `system`, và `new_size` sẽ là địa chỉ của chuỗi `"/bin/sh"`.

Một cấu trúc giả mạo có thể được thiết lập như sau:
- `fp->_flags = 0`
- `fp->_IO_buf_base = 0`
- `fp->_IO_buf_end = (bin_sh_addr - 100) / 2`
- `fp->_IO_write_ptr` = một giá trị lớn (ví dụ: `0xffffffff`)
- `fp->_IO_write_base = 0`
- Con trỏ hàm tại `((_IO_strfile *) fp)->_s._allocate_buffer` được ghi đè bằng địa chỉ của `system`.
Lưu ý: Nếu địa chỉ `bin_sh_addr` là số lẻ, ta cần cộng thêm 1 để tránh sai số do phép chia làm tròn xuống. Ngoài ra, thay vì `system("/bin/sh")`, có thể sử dụng các `one_gadget` để đơn giản hóa payload.
Luồng thực thi hoàn chỉnh sẽ là: `malloc_printerr` -> `__libc_message` -> `__GI_abort` -> `_IO_flush_all_lockp` -> `__GI__IO_str_overflow`.
Điểm khác biệt so với các kỹ thuật cũ (như _house-of-orange_) là phương pháp này không yêu cầu kẻ tấn công phải biết địa chỉ của heap. Vì `_IO_str_jumps` nằm trong `libc`, chỉ cần rò rỉ được địa chỉ của `libc` là đủ để thực hiện tấn công.
#### Sử dụng `_IO_str_finish`

Bên trong `_IO_str_jumps`, còn có một hàm khác là `_IO_str_finish` với điều kiện kiểm tra đơn giản hơn:

```C
void
_IO_str_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))             // Điều kiện
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);     // Lệnh gọi hàm có thể kiểm soát
  fp->_IO_buf_base = NULL;

  _IO_default_finish (fp, 0);
}
```

Để khai thác, ta chỉ cần đặt địa chỉ chuỗi `"/bin/sh"` vào `fp->_IO_buf_base`, ghi đè `_free_buffer` bằng địa chỉ của `system`, và đặt `fp->_flags = 0` là có thể vượt qua điều kiện.
Vấn đề là làm thế nào để kích hoạt `_IO_str_finish`. Mặc dù `fclose(fp)` là một cách, nó có thể không khả thi trong mọi tình huống. Một phương pháp hiệu quả hơn là quay lại luồng xử lý ngoại lệ. Hàm `_IO_flush_all_lockp` gọi `_IO_OVERFLOW`, vốn sẽ tìm đến `__GI__IO_str_overflow` dựa trên `offset` (độ dời) của con trỏ hàm `__overflow` trong `vtable`.

Bằng một thủ thuật nhỏ, nếu chúng ta làm cho con trỏ `fp` trỏ đến `địa_chỉ_của_vtable - offset_của_finish`, thì macro `_IO_OVERFLOW(fp)` sẽ tính toán và phân giải ra đúng địa chỉ của `_IO_str_finish` để thực thi nó.

Luồng thực thi hoàn chỉnh sẽ là: `malloc_printerr` -> `__libc_message` -> `__GI_abort` -> `_IO_flush_all_lockp` -> `__GI__IO_str_finish`.
### Sử dụng `_IO_wstr_jumps`
Tương tự `_IO_str_jumps`, `_IO_wstr_jumps` cũng là một `vtable` hợp lệ có thể được sử dụng để khai thác. Về cơ bản, kỹ thuật tấn công là tương tự.
``` C
// libio/wstrops.c

const struct _IO_jump_t _IO_wstr_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_wstr_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wstr_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wstr_underflow),
  // ...
};
```
#### Khai thác qua hàm `_IO_wstr_overflow`
Hàm này hoạt động với wide character (ký tự rộng), nhưng logic khai thác vẫn giữ nguyên.
``` C
_IO_wint_t
_IO_wstr_overflow (_IO_FILE *fp, _IO_wint_t c)
{
  // ...
  pos = fp->_wide_data->_IO_write_ptr - fp->_wide_data->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_wblen (fp) + flush_only))    // Điều kiện #define _IO_wblen(fp) ((fp)->_wide_data->_IO_buf_end - (fp)->_wide_data->_IO_buf_base)
    {
      if (fp->_flags2 & _IO_FLAGS2_USER_WBUF) /* not allowed to enlarge */
	return WEOF;
      else
	{
	  // ...
	  _IO_size_t new_size = 2 * old_wblen + 100;              // Cần tính toán new_size để new_size * sizeof(wchar_t) là địa chỉ của "/bin/sh"

	  // ...

	  new_buf
	    = (wchar_t *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size
									* sizeof (wchar_t));    // Ghi đè con trỏ hàm tại đây bằng địa chỉ của system
    // ...
}
```
#### Khai thác qua hàm `_IO_wstr_finish`
Hàm `_IO_wstr_finish` cũng cung cấp một vector tấn công tương tự.
``` C
void
_IO_wstr_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_wide_data->_IO_buf_base && !(fp->_flags2 & _IO_FLAGS2_USER_WBUF))    // Điều kiện
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_wide_data->_IO_buf_base);     // Ghi đè con trỏ hàm tại đây bằng địa chỉ của system
  fp->_wide_data->_IO_buf_base = NULL;

  _IO_wdefault_finish (fp, 0);
}
```
### Cập nhật mới nhất
Một commit gần đây trên nhánh `master` của `glibc` (dự kiến sẽ có mặt trong phiên bản `libc-2.28`) đã thay đổi cơ chế này.
Thay đổi này khá trực tiếp: thay thế các con trỏ hàm `_allocate_buffer` và `_free_buffer` trong cấu trúc `_IO_str_fields` bằng các lệnh gọi `malloc` và `free` tiêu chuẩn. Vì không còn sử dụng cơ chế gọi hàm qua con trỏ có thể bị ghi đè, kẻ tấn công không thể lợi dụng các `vtable` như `_IO_str_jumps` để vượt qua kiểm tra được nữa. Do đó, tất cả các kỹ thuật khai thác đã trình bày ở trên đều bị vô hiệu hóa.

---

Dưới đây là danh sách offset của các trường trong cấu trúc `_IO_FILE` (trên kiến trúc 64-bit) để tiện cho việc xây dựng payload:

```
0x0   _flags
0x8   _IO_read_ptr
0x10  _IO_read_end
0x18  _IO_read_base
0x20  _IO_write_base
0x28  _IO_write_ptr
0x30  _IO_write_end
0x38  _IO_buf_base
0x40  _IO_buf_end
0x48  _IO_save_base
0x50  _IO_backup_base
0x58  _IO_save_end
0x60  _markers
0x68  _chain
0x70  _fileno
0x74  _flags2
0x78  _old_offset
0x80  _cur_column
0x82  _vtable_offset
0x83  _shortbuf
0x88  _lock
0x90  _offset
0x98  _codecvt
0xa0  _wide_data
0xa8  _freeres_list
0xb0  _freeres_buf
0xb8  __pad5
0xc0  _mode
0xc4  _unused2
0xd8  vtable
```
## References
https://hackmd.io/@trhoanglan04/bof_advanced_level#define-vars
