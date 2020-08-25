# Protocol

## Mode of operation

  - Request mode of operation (target only)

```
&M
```

  - Debugger session, enables Debugger commands, will put FLAG_FOOBAR as the flag. Allowed only once as first command.

```
&D
```

  - Challenge mode, Debugger commands are disabled, will put Challenge's flag. Allowed only once as first command.

```
&C
```

  - Terminate Session by the client. Might be run at any time.

```
&T
```

## Messages

  - Exception message passed to the client before session close. Might be triggered by wrong command from the client or generic exception in emulator.

```
!ERROR TEXT$
```

  - Info text from the target.

```
#INFO TEXT$
```

## Application

  - Writing one unsigned char (in hex XX) (input for server and output for client):

```
@WXX
```

## Debugger

  - Generic answer for Step, Stop, Continue and Breakpoint hit from the Debugger. Contains information of PC, SP, Flags and registers values in HEX representation.

```
*I|CYCLES,PC,SP,FLAGS,R0,...,R31,[SP]$
*I|CYCLES,PC,SP,FLAGS,R0,...,R31$
```
  - Step. Optionally NUMBER of steps to proceed before stop.

```
*S|NUMBER$
```

  - Continue. Run the execution flow until Stop command received, Breakpoint or Exception occurs.

```
*C
```

  - Stop. Will interrupt previously issued Cont command.

```
*K
```

  - Trace toggle. Will print the registers state on each instruction run.

```
*T
```

  - Hit the Breakpoint NNNN (target only)

```
*B|NNNN
```

  - Break point info in response to List Breakpoints (target only). The "+" sign means enabled breakpoint.

```
*B#$
*B#-ADDR1$
*B#+ADDR1-ADDR2$
```

  - List Breakpoints

```
*B?
```

  - Set Breakpoint to ADDR

```
*B+ADDR
```

  - Remove Breakpotint number NNNN

```
*B-NNNN
```

  - Toggle Breakpotint number NNNN

```
*B!NNNN
```

  - Display registers

```
*R?
```

  - Update registers (NN is a number: R00 ... R31)

```
*R|NN=VVVV,NN=VVVV$
```

  - Memory dump. Easter Egg. Will return only FFFF...FF for any input ADDR

```
*X|ADDR
```

  - Memory dump response (target only)

```
*X|FFFF..FF$
```
