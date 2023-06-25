do
    local v17 = function()
        return _ENV
    end
    local function v23(v28, v29, ...)
        local v32
        local v33
        local v34
        local v35
        local v36
        local v37
        local v38
        local v39
        local v40
        local v41
        local v42
        local v43
            v33 = nil
            v34 = nil
            v35 = nil
            v36 = nil
            v37 = nil
            v38 = nil
            v39 = nil
            v40 = nil
            v41 = nil
            v42 = nil
                v43 = nil
                    v32 = 1
                    v33 = nil
                    v28 =
                        string.gsub(
                        string.sub(v28, 5),
                        "..",
                        function(v86)
                            if (string.byte(v86, 2) == (79)) then
                                v33 = tonumber(string.sub(v86, 1, 1))
                                return ""
                            else
                                local v110 = string.char(tonumber(v86, 16))
                                if v33 then
                                    local v138 = string.rep(v110, v33)
                                    v33 = nil
                                    return v138
                                else
                                    return v110
                                end
                            end
                        end
                    )
                    function v34(v77, v78, v79)
                        if v79 then
                            local v102 = (v77 / (2 ^ (v78 - 1))) % (2 ^ (((v79 - 1) - (v78 - 1)) + 1))
                            return v102 - (v102 % (1))
                        else
                            local v105 = 2 ^ (v78 - 1)
                            return (((v77 % (v105 + v105)) >= v105) and (1)) or (0)
                        end
                    end
                    function v35()
                        local v71
                        local v72 = string.byte(v28, v32, v32)
                        v32 = v32 + 1
                        return v72
                    end
                    function v36()
                        local v75
                        local v76
                        v75, v76 = string.byte(v28, v32, v32 + 2)
                        v32 = v32 + 2
                        return (v76 * 256) + v75
                    end
                    function v37()
                        local v82
                        local v83
                        local v84
                        local v85
                        v82, v83, v84, v85 = string.byte(v28, v32, v32 + 3)
                        v32 = v32 + 4
                        return (v85 * 16777216) + (v84 * 65536) + (v83 * 256) + v82
                    end
                    function v38()
                        local v94
                        local v95
                        local v96
                        local v97
                        local v98
                        local v99
                        v94 = v37()
                        v95 = v37()
                        v96 = 1
                        v97 = (v34(v95, 1, 20) * 4294967296) + v94
                        v98 = v34(v95, 21, 31)
                        v99 = ((v34(v95, 32) == (1)) and -1) or 1
                        if (v98 == 0) then
                            if (v97 == 0) then
                                return v99 * 0
                            else
                                v98 = 1
                                v96 = 0
                            end
                        elseif (v98 == (2047)) then
                            return ((v97 == (0)) and (v99 * ((1) / 0))) or (v99 * NaN)
                        end
                        return math.ldexp(v99, v98 - 1023) * (v96 + (v97 / (4503599627370496)))
                    end
                    function v39(v87)
                        local v90
                        local v91
                        v90 = nil
                        v88 = 1
                        v91 = nil
                        v90 = nil
                        if not v87 then
                            v87 = v37()
                            if (v87 == 0) then
                                return ""
                            end
                        end
                        v90 = string.sub(v28, v32, (v32 + v87) - 1)
                        v32 = v32 + v87
                        v91 = {}
                        for v163 = 1, #v90 do
                            v91[v163] = string.char(string.byte(string.sub(v90, v163, v163)))
                        end
                        return table.concat(v91)
                    end
                    v40 = v37
                    function v41(...)
                        return {...}, select("#", ...)
                    end
                    function v42()
                        local v56
                        local v57
                        local v58
                        local v59
                        local v60
                        local v61
                        v56 = {}
                        v57 = {}
                        v58 = {}
                        v59 = {v56, v57, nil, v58}
                        v60 = v37()
                        v61 = {}
                        for v143 = 1, v60 do
                            local v147 = nil
                            local v146 = v35()
                            if (v146 == 1) then
                                v147 = v35() ~= (0)
                            elseif (v146 == (2)) then
                                v147 = v38()
                            elseif (v146 == (3)) then
                                v147 = v39()
                            end
                            v61[v143] = v147
                        end
                        v59[3] = v35()
                        for v148 = 1, v37() do
                            local v150
                            local v151
                            v150 = 0
                            v151 = nil
                            v151 = v35()
                            if (v34(v151, 1, 1) == (0)) then
                                local v178
                                local v179
                                local v180
                                v177 = 0
                                v178 = v34(v151, 2, 3)
                                v179 = v34(v151, 4, 6)
                                v180 = {v36(), v36(), nil, nil}
                                if (v178 == 0) then
                                    v180[3] = v36()
                                    v180[4] = v36()
                                elseif (v178 == 1) then
                                    v180[3] = v37()
                                elseif (v178 == (2)) then
                                    v180[3] = v37() - 65536
                                elseif (v178 == (3)) then
                                    v180[3] = v37() - 65536
                                    v180[4] = v36()
                                end
                                if (v34(v179, 1, 1) == (1)) then
                                    v180[2] = v61[v180[2]]
                                end
                                if (v34(v179, 2, 2) == (1)) then
                                    v180[3] = v61[v180[3]]
                                end
                                if (v34(v179, 3, 3) == (1)) then
                                    v180[4] = v61[v180[4]]
                                end
                                v56[v148] = v180
                            end
                        end
                        for v152 = 1, v37() do
                            v57[v152 - 1] = v42()
                        end
                        for v154 = 1, v37() do
                            v58[v154] = v37()
                        end
                        return v59
                    end
                            function v43(v62, v63, v64)
                                local v67
                                local v68
                                local v69
                                        v67 = nil
                                        v68 = nil
                                        v69 = nil
                                                        v67 = v62[1]
                                                        v68 = v62[2]
                                                        v69 = v62[3]
                                                        return function(...)
                                                            local v158
                                                            local v159
                                                            local v160
                                                            local v161
                                                            local v162
                                                            v159 = nil
                                                            v160 = nil
                                                            v157 = 0
                                                            v158 = nil
                                                            v161 = nil
                                                            v162 = nil
                                                            v158 = 1
                                                            v159 = -1
                                                            v160 = {...}
                                                            v161 = select("#", ...) - 1
                                                            function v162()
                                                                local v185
                                                                local v186
                                                                local v187
                                                                local v188
                                                                local v189
                                                                local v190
                                                                local v191
                                                                local v192
                                                                local v193
                                                                local v194
                                                                v185 = v67
                                                                v186 = v68
                                                                v187 = v69
                                                                v188 = v41
                                                                v189 = {}
                                                                v190 = {}
                                                                v191 = {}
                                                                for v199 = 0, v161 do
                                                                    if (v199 >= v187) then
                                                                        v189[v199 - v187] = v160[v199 + 1]
                                                                    else
                                                                        v191[v199] = v160[v199 + 1]
                                                                    end
                                                                end
                                                                v192 = (v161 - v187) + 1
                                                                while true do -- might be real while
                                                                    v193 = v185[v158]
                                                                    v194 = v193[1]
                                                                    if (v194 <= 14) then
                                                                        if (v194 <= (6)) then
                                                                            if (v194 <= (2)) then
                                                                                if (v194 <= (0)) then
                                                                                    local v225
                                                                                    v225 = v193[2]
                                                                                    return table.unpack(
                                                                                        v191,
                                                                                        v225,
                                                                                        v159
                                                                                    )
                                                                                elseif (v194 > (1)) then
                                                                                    v191[v193[2]] =
                                                                                        v191[v193[3]] % v193[4]
                                                                                else
                                                                                    v191[v193[2]] =
                                                                                        v191[v193[3]] - v193[4]
                                                                                end
                                                                            elseif (v194 <= (4)) then
                                                                                if (v194 == (3)) then
                                                                                    v158 = v193[3]
                                                                                elseif (v191[v193[2]] == v191[v193[4]]) then
                                                                                    v158 = v158 + 1
                                                                                else
                                                                                    v158 = v193[3]
                                                                                end
                                                                            elseif (v194 > (5)) then
                                                                                v191[v193[2]] = v191[v193[3]]
                                                                            else
                                                                                v191[v193[2]] = v191[v193[3]] + v193[4]
                                                                            end
                                                                        elseif (v194 <= 10) then
                                                                            if (v194 <= (8)) then
                                                                                if (v194 == (7)) then
                                                                                    local v239
                                                                                    local v240
                                                                                    v240 = v193[2]
                                                                                    v191[v240](v191[v240 + 1])
                                                                                else
                                                                                    v191[v193[2]] = {}
                                                                                end
                                                                            elseif (v194 == (9)) then
                                                                                local v244
                                                                                local v245
                                                                                local v246
                                                                                v244 = v186[v193[3]]
                                                                                v245 = nil
                                                                                v246 = {}
                                                                                v245 =
                                                                                    setmetatable(
                                                                                    {},
                                                                                    {
                                                                                        ["__index"] = function(
                                                                                            v346,
                                                                                            v347)
                                                                                            local v350
                                                                                            v350 = v246[v347]
                                                                                            return v350[1][v350[2]]
                                                                                        end,
                                                                                        ["__newindex"] = function(
                                                                                            v351,
                                                                                            v352,
                                                                                            v353)
                                                                                            local v356
                                                                                            v356 = v246[v352]
                                                                                            v356[1][v356[2]] = v353
                                                                                        end
                                                                                    }
                                                                                )
                                                                                for v327 = 1, v193[4] do
                                                                                    local v330
                                                                                    v158 = v158 + 1
                                                                                    v330 = v185[v158]
                                                                                    if (v330[1] == (6)) then
                                                                                        v246[v327 - 1] = {v191, v330[3]}
                                                                                    else
                                                                                        v246[v327 - 1] = {v63, v330[3]}
                                                                                    end
                                                                                    v190[#v190 + 1] = v246
                                                                                end
                                                                                v191[v193[2]] = v43(v244, v245, v64)
                                                                            else
                                                                                local v248
                                                                                local v249
                                                                                local v250
                                                                                local v251
                                                                                v249 = v193[2]
                                                                                v250 = v191[v249 + 2]
                                                                                v251 = v191[v249] + v250
                                                                                v191[v249] = v251
                                                                                if (v250 > (0)) then
                                                                                    if (v251 <= v191[v249 + 1]) then
                                                                                        v158 = v193[3]
                                                                                        v191[v249 + 3] = v251
                                                                                    end
                                                                                elseif (v251 >= v191[v249 + 1]) then
                                                                                    v158 = v193[3]
                                                                                    v191[v249 + 3] = v251
                                                                                end
                                                                            end
                                                                        elseif (v194 <= (12)) then
                                                                            if (v194 == 11) then
                                                                                local v254
                                                                                v254 = v193[2]
                                                                                v191[v254] =
                                                                                    v191[v254](
                                                                                    table.unpack(v191, v254 + 1, v159)
                                                                                )
                                                                            else
                                                                                do
                                                                                    return
                                                                                end
                                                                            end
                                                                        elseif (v194 == (13)) then
                                                                            v191[v193[2]] = v63[v193[3]]
                                                                        else
                                                                            v191[v193[2]] = v193[3]
                                                                        end
                                                                    elseif (v194 <= (21)) then
                                                                        if (v194 <= (17)) then
                                                                            if (v194 <= (15)) then
                                                                                local v228
                                                                                local v229
                                                                                local v230
                                                                                local v231
                                                                                v228 = v193[2]
                                                                                v229, v230 =
                                                                                    v188(
                                                                                    v191[v228](
                                                                                        table.unpack(
                                                                                            v191,
                                                                                            v228 + 1,
                                                                                            v193[3]
                                                                                        )
                                                                                    )
                                                                                )
                                                                                v159 = (v230 + v228) - 1
                                                                                v231 = 0
                                                                                for v304 = v228, v159 do
                                                                                    v231 = v231 + 1
                                                                                    v191[v304] = v229[v231]
                                                                                end
                                                                            elseif (v194 == (16)) then
                                                                                local v261
                                                                                local v262
                                                                                local v263
                                                                                local v264
                                                                                v261 = v193[2]
                                                                                v262, v263 =
                                                                                    v188(v191[v261](v191[v261 + 1]))
                                                                                v159 = (v263 + v261) - 1
                                                                                v264 = 0
                                                                                for v332 = v261, v159 do
                                                                                    v264 = v264 + 1
                                                                                    v191[v332] = v262[v264]
                                                                                end
                                                                            else
                                                                                v64[v193[3]] = v191[v193[2]]
                                                                            end
                                                                        elseif (v194 <= 19) then
                                                                            if (v194 > (18)) then
                                                                                v191[v193[2]] =
                                                                                    v191[v193[3]] % v191[v193[4]]
                                                                            else
                                                                                v191[v193[2]] = #v191[v193[3]]
                                                                            end
                                                                        elseif (v194 > (20)) then
                                                                            local v271
                                                                            local v272
                                                                            local v273
                                                                            v271 = v193[2]
                                                                            v272 = v191[v271]
                                                                            v273 = v191[v271 + 2]
                                                                            if (v273 > 0) then
                                                                                if (v272 > v191[v271 + 1]) then
                                                                                    v158 = v193[3]
                                                                                else
                                                                                    v191[v271 + 3] = v272
                                                                                end
                                                                            elseif (v272 < v191[v271 + 1]) then
                                                                                v158 = v193[3]
                                                                            else
                                                                                v191[v271 + 3] = v272
                                                                            end
                                                                        else
                                                                            local v276
                                                                            local v277
                                                                            local v278
                                                                            local v279
                                                                            v276 = v193[2]
                                                                            v277, v278 =
                                                                                v188(
                                                                                v191[v276](
                                                                                    table.unpack(v191, v276 + 1, v159)
                                                                                )
                                                                            )
                                                                            v159 = (v278 + v276) - 1
                                                                            v279 = 0
                                                                            for v335 = v276, v159 do
                                                                                v279 = v279 + 1
                                                                                v191[v335] = v277[v279]
                                                                            end
                                                                        end
                                                                    elseif (v194 <= (25)) then
                                                                        if (v194 <= 23) then
                                                                            if (v194 > (22)) then
                                                                                v191[v193[2]] = v193[3] + v191[v193[4]]
                                                                            elseif not v191[v193[2]] then
                                                                                v158 = v158 + 1
                                                                            else
                                                                                v158 = v193[3]
                                                                            end
                                                                        elseif (v194 > (24)) then
                                                                            local v283
                                                                            v283 = v193[2]
                                                                            v191[v283] =
                                                                                v191[v283](
                                                                                table.unpack(v191, v283 + 1, v193[3])
                                                                            )
                                                                        else
                                                                            v191[v193[2]] = v191[v193[3]][v193[4]]
                                                                        end
                                                                    elseif (v194 <= (27)) then
                                                                        if (v194 == (26)) then
                                                                            local v287
                                                                            local v288
                                                                            v288 = v193[2]
                                                                            do
                                                                                return v191[v288](
                                                                                    table.unpack(
                                                                                        v191,
                                                                                        v288 + 1,
                                                                                        v193[3]
                                                                                    )
                                                                                )
                                                                            end
                                                                        else
                                                                            v191[v193[2]] = v64[v193[3]]
                                                                        end
                                                                    elseif (v194 == 28) then
                                                                        local v293
                                                                        v293 = v193[2]
                                                                        v191[v293](table.unpack(v191, v293 + 1, v159))
                                                                    else
                                                                        local v296
                                                                        v296 = v193[2]
                                                                        v191[v296] = v191[v296]()
                                                                    end
                                                                    v158 = v158 + 1
                                                                end
                                                            end
                                                            _G["A"], _G["B"] = v41(pcall(v162))
                                                            if not _G["A"][1] then
                                                                local v183
                                                                v183 = v62[4][v158] or "?"
                                                                error("Script error at [" .. v183 .. "]:" .. _G["A"][2])
                                                            else
                                                                return table.unpack(_G["A"], 2, _G["B"])
                                                            end
                                                        end
                                                    end
                            return v43(v42(), {}, v29)(...)
    end
    v23(
        "MATT1C3O0003063O00737472696E6703043O006368617203043O00627974652O033O0073756203053O0062697433322O033O0062697403043O0062786F7203053O007461626C6503063O00636F6E63617403063O00696E7365727403023O00696F03053O00777269746503293O00205O5F9O204O205F5O203O5F205O5F204O5F200A03293O007C3O202O5F7C3O5F203O5F203O5F7C207C3O5F7C3O207C5F3O205F7C2O202O5F7C0A03293O007C2O207C2O207C202E207C202E207C202E207C207C202D5F7C202D3C2O207C207C207C2O202O5F7C0A03293O007C5O5F7C3O5F7C3O5F7C5F2O207C5F7C3O5F7C3O5F7C207C5F7C207C5F7C3O200A032A3O009O205O207C3O5F7C7O205A65724D612O74202D206D697363200A03023O00409103083O007EB1A3BB4586DBA703013O007303043O007265616403373O00DF17EB31E4E81CC12FC4EF37F223D1C334CC39FAF22CD915C4C321D43EC0FF2CC92FFAFE22DE2FFAEF22C32EC7F33BF22FD6FF22DD2FD803053O009C43AD4AA503053O007072696E742O033O00711D9903073O002654D72976DC4603043O00D27F250703053O009E30764272004A3O00121B3O00013O0020185O000200121B000100013O00201800010001000300121B000200013O00201800020002000400121B000300053O0006160003000A000100010004033O000A000100121B000300063O00201800040003000700121B000500083O00201800050005000900121B000600083O00201800060006000A00060900073O000100062O00063O00064O00068O00063O00044O00063O00014O00063O00024O00063O00053O00121B0008000B3O00201800080008000C00120E0009000D4O000700080002000100121B0008000B3O00201800080008000C00120E0009000E4O000700080002000100121B0008000B3O00201800080008000C00120E0009000F4O000700080002000100121B0008000B3O00201800080008000C00120E000900104O000700080002000100121B0008000B3O00201800080008000C00120E000900114O000700080002000100121B0008000B3O00201800080008000C2O0006000900073O00120E000A00123O00120E000B00134O000F0009000B4O001C00083O000100121B0008000B3O0020180008000800152O001D000800010002001211000800143O00121B000800144O0006000900073O00120E000A00163O00120E000B00174O00190009000B000200060400080043000100090004033O0043000100121B000800184O0006000900073O00120E000A00193O00120E000B001A4O000F0009000B4O001C00083O00010004033O0049000100121B000800184O0006000900073O00120E000A001B3O00120E000B001C4O000F0009000B4O001C00083O00012O000C3O00013O00013O00023O00026O00F03F026O00704002284O000800025O00120E000300014O001200045O00120E000500013O0004150003002300012O000D00076O0006000800024O000D000900014O000D000A00024O000D000B00034O000D000C00044O0006000D6O0006000E00063O002005000F000600012O000F000C000F4O000B000B3O00022O000D000C00034O000D000D00044O0006000E00013O002001000F000600012O0012001000014O0013000F000F0010001017000F0001000F0020010010000600012O0012001100014O00130010001000110010170010000100100020050010001000012O000F000D00104O0014000C6O000B000A3O0002002002000A000A00022O00100009000A4O001C00073O000100040A0003000500012O000D000300054O0006000400024O001A000300046O00036O000C3O00017O00283O00093O000A3O000A3O000A3O000A3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000B3O000A3O000D3O000D3O000D3O000D3O000E3O004A3O00013O00013O00023O00023O00033O00033O00043O00043O00043O00043O00053O00063O00063O00073O00073O000E3O000E3O000E3O000E3O000E3O000E3O000E3O000F3O000F3O000F3O000F3O00103O00103O00103O00103O00113O00113O00113O00113O00123O00123O00123O00123O00133O00133O00133O00133O00143O00143O00143O00143O00143O00143O00143O00153O00153O00153O00153O00163O00163O00163O00163O00163O00163O00163O00173O00173O00173O00173O00173O00173O00173O00193O00193O00193O00193O00193O00193O001A3O00",
        v17(),
        ...
    )
end
