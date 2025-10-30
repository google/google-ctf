def IN(s): first((s == .) // empty) // false;


[(.modules.program.ports.[] | select(.direction == "output") | .bits[] | tostring)] as $OUTPUTS |
[(.modules.program.ports.[] | select(.direction == "input") | .bits[] | tostring)] as $INPUTS |

def deref(w): if w then (
    w // "" | tostring as $w |
    (if $w | IN($INPUTS[]) then ("D, " + ($INPUTS | index($w) | tostring)) else ("W, W_" + $w) end)) else null end;

(
    (
        [
            .modules.program.cells.[] |
            {
                "key": (.connections.Y[0] | tostring),
                "value": {
                    "function": .type,
                    "A": deref(.connections.A[0]),
                    "B": deref(.connections.B[0])
                }
            }
        ] | from_entries
    ) + {
        "x": {
            "function": "$_ZERO_",
            "A": null,
            "B": null
        }
    }
) as $WIRES |


(
    ["%include \"./header.asm\""] + (
        $OUTPUTS | map("$_REF_ W_" + .)
    ) + (
        $WIRES | to_entries |
            map(
                "W_" + .key + ":" +
                 (.value.function + (
                    if .value.A then
                        " " + .value.A + (
                            if .value.B then ", " + .value.B else "" end
                        ) else "" end
                ))
            )
        )
) | join("\n")
