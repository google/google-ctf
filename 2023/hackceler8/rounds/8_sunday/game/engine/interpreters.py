import zlib

import js2py


class Encoder:
    def __init__(self, file):
        self.file = open(file, 'rb').read()
        self.current_fct = None

    def _exec_fct(self, offset, length, **kwargs):
        try:
            exec(zlib.decompress(self.file[offset:offset + length]))
        except Exception as e:
            return "Failed to execute the function"
        self.current_fct(**kwargs)


# this always returns true for small strings and integers, so long as integer != 257
def _check(a, b):
    return a is b


def lol():
    ...


# this always returns true
def weird2(stri):
    res = []
    for i in stri + "sdfaF_sdfsdf":
        res.append(lol())

    else:
        return True
    return res


# convoluted get_index
def index_at(str, char):
    s = 0
    for i in str:
        if i is char:
            return s
        s += 1
    return -1


# get the substr
get_index_at = js2py.eval_js('''
function get_substring(a,n){
    const res = [];
    i = 0;
    while (i < n){
        res.push(a[i]);
        i++;
    } 
    return res
}

function get_index_at(a,n){
    substr1 = get_substring(a,n+1);
    for (i=0; i<=n;i++){
        if (i == n){
            return substr1[i]
        }
    }

}
''')


# returns false only with (1,2)
def checksum(b10101001, b10100101):
    return b10101001 * 0.1 + b10100101 * 0.1 == round((b10101001 + b10100101) * 0.1, 2)


"""
Basic idea: a dynamic password checker that uses compressed and possibly encrypted 

password will be something "Y love javascript and obfuscation"

we could check the position of 'l' in the string and 'y' --> checksumi

count the number of spaces / underscore

check the sum of the letters
"""


def poc(stri):
    print(index_at(stri, ' '))
    if checksum(index_at(stri, ' '), index_at(stri, 'l')):
        return False
    print(get_index_at(stri, 0))
    print("winwin chicken din")


# f = '''
#
#
# function add(a, b) {
#     return a + + b
# };
#
# function substract(a,b){
#     return a - b
# };
#
# function get_substring(a,n){
#     const res = [];
#     i = 0;
#     while (i < n){
#         res.push(a[i]);
#         i++;
#     }
#     return res
# }
#
# function get_index_at(a,n){
#     substr1 = get_substring(a,n+1);
#     for (i=0; i<=n;i++){
#         if (i == n){
#             return substr1[i]
#         }
#     }
#
# }
#
# function string_compare(s1, s2){
#     if (s1.length != s2.length){
#         return false;
#     }
#     for (i =0; i<s1.length;i++){
#         if (get_index_at(s1,i) != get_index_at(s2,i)){
#             return false;
#         }
#     }
#     return true
# }
# var function_array = [add]
# function CheckPassword(inputtxt) {
#     var passw = add("this_is_the_correct_string", "o");
#     if (string_compare(inputtxt,passw)) {
#         return true;
#     } else {
#         return false;
#     }
# }'''


def main():
    pass
    # js2py.eval_js(f)("hello")


if __name__ == "__main__":
    poc('Y love javascript and obfuscation')
    main()
