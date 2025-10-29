// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

module program(
    input  [63:0] counter,
    output logic [783:0] pixels
);
    logic [63:0] pixel_array [7:0];
    genvar i;
    generate
        for (i = 0; i < 8; i = i + 1) begin : gen_pixel_selectors
            wire [3:0] nibble;
            assign nibble = counter[i*4 +: 4];
            wire [63:0] pixel_output;

            always_comb begin
                case (nibble)
                    4'd0: pixel_output =  64'b0111111011000011110000111100001111000011110000111100001101111110;
                    4'd1: pixel_output =  64'b0011100000011000000110000001100000011000000110000001100000111100;
                    4'd2: pixel_output =  64'b1111111011111111000000110111111111111110110000001111111111111111;
                    4'd3: pixel_output =  64'b1111111011111111000000110011111100111111000000111111111111111110;
                    4'd4: pixel_output =  64'b1100001111000011110000111111111101111111000000110000001100000011;
                    4'd5: pixel_output =  64'b1111111111111111110000001111111011111111000000111111111111111110;
                    4'd6: pixel_output =  64'b0111111011111111110000001111111011111111110000111111111101111110;
                    4'd7: pixel_output =  64'b1111111111111111000000110000001100000011000000110000001100000011;
                    4'd8: pixel_output =  64'b0111111011000011110000110111111001111110110000111100001101111110;
                    4'd9: pixel_output =  64'b0111111011111111110000111100001111111111011111110000001100000011;
                    4'd10: pixel_output = 64'b0011110001111110011001101100001111111111111111111100001111000011;
                    4'd11: pixel_output = 64'b1111111011111111110000111111111011111110110000111111111111111110;
                    4'd12: pixel_output = 64'b0111111111111111111000001100000011000000111000001111111101111111;
                    4'd13: pixel_output = 64'b1111110011111110110001111100001111000011110001111111111011111100;
                    4'd14: pixel_output = 64'b1111111111111111110000001111100011111000110000001111111111111111;
                    4'd15: pixel_output = 64'b1111111111111111110000001111110011111100110000001100000011000000;
                    default: pixel_output = 64'b0;
                endcase
            end

            assign pixel_array[i] = pixel_output;
        end
    endgenerate

    assign pixels[63:0] = counter - 1;
    assign {pixels[600], pixels[599], pixels[598], pixels[597], pixels[596], pixels[595], pixels[594], pixels[593],
            pixels[601], pixels[506], pixels[505], pixels[504], pixels[503], pixels[502], pixels[501], pixels[500],
            pixels[602], pixels[507], pixels[420], pixels[419], pixels[418], pixels[417], pixels[416], pixels[415],
            pixels[603], pixels[508], pixels[421], pixels[342], pixels[341], pixels[340], pixels[339], pixels[338],
            pixels[604], pixels[509], pixels[422], pixels[343], pixels[272], pixels[271], pixels[270], pixels[269],
            pixels[605], pixels[510], pixels[423], pixels[344], pixels[273], pixels[210], pixels[209], pixels[208],
            pixels[606], pixels[511], pixels[424], pixels[345], pixels[274], pixels[211], pixels[156], pixels[155],
            pixels[607], pixels[512], pixels[425], pixels[346], pixels[275], pixels[212], pixels[157], pixels[110]
           } = pixel_array[0];

    assign {pixels[591], pixels[590], pixels[589], pixels[588], pixels[587], pixels[586], pixels[585], pixels[584],
            pixels[498], pixels[497], pixels[496], pixels[495], pixels[494], pixels[493], pixels[492], pixels[491],
            pixels[413], pixels[412], pixels[411], pixels[410], pixels[409], pixels[408], pixels[407], pixels[406],
            pixels[336], pixels[335], pixels[334], pixels[333], pixels[332], pixels[331], pixels[330], pixels[329],
            pixels[267], pixels[266], pixels[265], pixels[264], pixels[263], pixels[262], pixels[261], pixels[260],
            pixels[206], pixels[205], pixels[204], pixels[203], pixels[202], pixels[201], pixels[200], pixels[199],
            pixels[153], pixels[152], pixels[151], pixels[150], pixels[149], pixels[148], pixels[147], pixels[146],
            pixels[108], pixels[107], pixels[106], pixels[105], pixels[104], pixels[103], pixels[102], pixels[101]
           } = pixel_array[1];

    assign {pixels[582], pixels[581], pixels[580], pixels[579], pixels[578], pixels[577], pixels[576], pixels[675],
            pixels[489], pixels[488], pixels[487], pixels[486], pixels[485], pixels[484], pixels[575], pixels[674],
            pixels[404], pixels[403], pixels[402], pixels[401], pixels[400], pixels[483], pixels[574], pixels[673],
            pixels[327], pixels[326], pixels[325], pixels[324], pixels[399], pixels[482], pixels[573], pixels[672],
            pixels[258], pixels[257], pixels[256], pixels[323], pixels[398], pixels[481], pixels[572], pixels[671],
            pixels[197], pixels[196], pixels[255], pixels[322], pixels[397], pixels[480], pixels[571], pixels[670],
            pixels[144], pixels[195], pixels[254], pixels[321], pixels[396], pixels[479], pixels[570], pixels[669],
            pixels[143], pixels[194], pixels[253], pixels[320], pixels[395], pixels[478], pixels[569], pixels[668]
           } = pixel_array[2];

    assign {pixels[609], pixels[514], pixels[427], pixels[348], pixels[277], pixels[214], pixels[159], pixels[112],
            pixels[610], pixels[515], pixels[428], pixels[349], pixels[278], pixels[215], pixels[160], pixels[113],
            pixels[611], pixels[516], pixels[429], pixels[350], pixels[279], pixels[216], pixels[161], pixels[114],
            pixels[612], pixels[517], pixels[430], pixels[351], pixels[280], pixels[217], pixels[162], pixels[115],
            pixels[613], pixels[518], pixels[431], pixels[352], pixels[281], pixels[218], pixels[163], pixels[116],
            pixels[614], pixels[519], pixels[432], pixels[353], pixels[282], pixels[219], pixels[164], pixels[117],
            pixels[615], pixels[520], pixels[433], pixels[354], pixels[283], pixels[220], pixels[165], pixels[118],
            pixels[616], pixels[521], pixels[434], pixels[355], pixels[284], pixels[221], pixels[166], pixels[119]
           } = pixel_array[3];

    assign {pixels[141], pixels[192], pixels[251], pixels[318], pixels[393], pixels[476], pixels[567], pixels[666],
            pixels[140], pixels[191], pixels[250], pixels[317], pixels[392], pixels[475], pixels[566], pixels[665],
            pixels[139], pixels[190], pixels[249], pixels[316], pixels[391], pixels[474], pixels[565], pixels[664],
            pixels[138], pixels[189], pixels[248], pixels[315], pixels[390], pixels[473], pixels[564], pixels[663],
            pixels[137], pixels[188], pixels[247], pixels[314], pixels[389], pixels[472], pixels[563], pixels[662],
            pixels[136], pixels[187], pixels[246], pixels[313], pixels[388], pixels[471], pixels[562], pixels[661],
            pixels[135], pixels[186], pixels[245], pixels[312], pixels[387], pixels[470], pixels[561], pixels[660],
            pixels[134], pixels[185], pixels[244], pixels[311], pixels[386], pixels[469], pixels[560], pixels[659]
           } = pixel_array[4];

    assign {pixels[618], pixels[523], pixels[436], pixels[357], pixels[286], pixels[223], pixels[168], pixels[121],
            pixels[619], pixels[524], pixels[437], pixels[358], pixels[287], pixels[224], pixels[169], pixels[170],
            pixels[620], pixels[525], pixels[438], pixels[359], pixels[288], pixels[225], pixels[226], pixels[227],
            pixels[621], pixels[526], pixels[439], pixels[360], pixels[289], pixels[290], pixels[291], pixels[292],
            pixels[622], pixels[527], pixels[440], pixels[361], pixels[362], pixels[363], pixels[364], pixels[365],
            pixels[623], pixels[528], pixels[441], pixels[442], pixels[443], pixels[444], pixels[445], pixels[446],
            pixels[624], pixels[529], pixels[530], pixels[531], pixels[532], pixels[533], pixels[534], pixels[535],
            pixels[625], pixels[626], pixels[627], pixels[628], pixels[629], pixels[630], pixels[631], pixels[632]
           } = pixel_array[5];

    assign {pixels[123], pixels[124], pixels[125], pixels[126], pixels[127], pixels[128], pixels[129], pixels[130],
            pixels[172], pixels[173], pixels[174], pixels[175], pixels[176], pixels[177], pixels[178], pixels[179],
            pixels[229], pixels[230], pixels[231], pixels[232], pixels[233], pixels[234], pixels[235], pixels[236],
            pixels[294], pixels[295], pixels[296], pixels[297], pixels[298], pixels[299], pixels[300], pixels[301],
            pixels[367], pixels[368], pixels[369], pixels[370], pixels[371], pixels[372], pixels[373], pixels[374],
            pixels[448], pixels[449], pixels[450], pixels[451], pixels[452], pixels[453], pixels[454], pixels[455],
            pixels[537], pixels[538], pixels[539], pixels[540], pixels[541], pixels[542], pixels[543], pixels[544],
            pixels[634], pixels[635], pixels[636], pixels[637], pixels[638], pixels[639], pixels[640], pixels[641]
           } = pixel_array[6];

    assign {pixels[132], pixels[183], pixels[242], pixels[309], pixels[384], pixels[467], pixels[558], pixels[657],
            pixels[181], pixels[182], pixels[241], pixels[308], pixels[383], pixels[466], pixels[557], pixels[656],
            pixels[238], pixels[239], pixels[240], pixels[307], pixels[382], pixels[465], pixels[556], pixels[655],
            pixels[303], pixels[304], pixels[305], pixels[306], pixels[381], pixels[464], pixels[555], pixels[654],
            pixels[376], pixels[377], pixels[378], pixels[379], pixels[380], pixels[463], pixels[554], pixels[653],
            pixels[457], pixels[458], pixels[459], pixels[460], pixels[461], pixels[462], pixels[553], pixels[652],
            pixels[546], pixels[547], pixels[548], pixels[549], pixels[550], pixels[551], pixels[552], pixels[651],
            pixels[643], pixels[644], pixels[645], pixels[646], pixels[647], pixels[648], pixels[649], pixels[650]
           } = pixel_array[7];
endmodule
