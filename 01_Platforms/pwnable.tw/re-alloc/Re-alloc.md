Reallocate:
``` C
int reallocate()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-18h]
  unsigned __int64 size; // [rsp+10h] [rbp-10h]
  void *v3; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v1 = read_long();
  if ( v1 > 1 || !heap[v1] )
    return puts("Invalid !");
  printf("Size:");
  size = read_long();
  if ( size > 0x78 )
    return puts("Too large!");
  v3 = realloc((void *)heap[v1], size);
  if ( !v3 )
    return puts("alloc error");
  heap[v1] = v3;
  printf("Data:");
  return read_input(heap[v1], (unsigned int)size);
}
```
rfree:
```C
int rfree()
{
  _QWORD *v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    realloc((void *)heap[v2], 0LL);
    v0 = heap;
    heap[v2] = 0LL;
  }
  return (int)v0;
}
```
Chú ý realloc (ptr, 0) sẽ là free vậy khi chúng ta lựa chọn realloc với giá trị 0, và chọn free 1 lần nữa và bùm => Lỗi double free:
![[Pasted image 20251013153345.png]]
![[Pasted image 20251013153646.png]]
### analyse
- case1: tạo chunk ptr (tối đa 2 chunks)
- case2: sửa chunk ptr
- case3: xoá chunk ptr
- case4: thoát chương trình
- BUG nằm ở **realloc**, nếu **size** = 0 thì **realloc** tương tự **free**
- ở case3 **free** bình thường bao gồm xoá con trỏ **ptr**, nhưng chỉ cần **free** mà không xoá sẽ có UAF vuln
