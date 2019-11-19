;; Copyright 2019 Google LLC

;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at

;;     https://www.apache.org/licenses/LICENSE-2.0

;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

Hello again!
1. Open this file in Emacs
2. Enter the flag here: CTF{  n  0  _  D  1  y  R  D  o  4  _  1  y  r  o  _W i  _  _ u 5}
   Use only [a-zA-Z0-9_] plz. Also, I filled in some of the characters for you 'cause I'm such a nice guy.
3. Place your cursor here and press C-M-x
                     |
                     |
+--------------------+
|
|
v
(progn
  (setq max-lisp-eval-depth 200000)
  (setq max-specpdl-size 200000)
  (defun n ()
    (forward-list) (eval-defun nil))
  (defun w (x y)
    (save-excursion
      (goto-char x)
      (delete-char 2)
      (insert (format "%02x" y)))
    (n))
  (defun i (x)
    (string-to-number (buffer-substring x (+ 2 x)) 16))
  (defun c (x)
    (char-after x))
  (defmacro s (x y)
    `(progn (setq ,x ,y) (n)))
  (defun r(x)
    (setq i 0)
    (setq n x)
    (setq s (point))
    (n))
  (defun e ()
    (setq i (1+ i))
    (if (= i n) (n)
      (progn (goto-char s) (n))))
  (defun m (x)
    (delete-and-extract-region 939 (1+ (buffer-size))) (insert x))
  (defun p ()
    (m "Nice, you got it! :)"))
  (defun f ()
    (m "BZZZT, that's wrong :C"))
  (goto-char 1708) (n))

(s a '(24 28 27 29 10 16 6 7 4 21 4 23 11 10 16 8 14 29 3 21 16 19 2 3 23 12 20 6 3 30 12 15 23 11 29 12 18 9 25 4 17 19 23 1 28 12 30 11 27 14 16 6 19 0 26 1 31 15 11 12 7))
(r 61)
(s f (c (+ 652 i)))
(s c (lsh f -3))
(s p (logand f #b111))
(if (= (logxor c #x16) (nth i a)) (n) (f))
(if (= p 0) (w 1969 (logxor (i 1969) #x19))
  (if (= p 1) (w 1969 (logxor (i 1969) #x15))
    (if (= p 2) (w 1969 (logxor (i 1969) #x04))
      (if (= p 3) (w 1969 (logxor (i 1969) #x18))
        (if (= p 4) (w 1969 (logxor (i 1969) #x1c))
          (if (= p 5) (w 1969 (logxor (i 1969) #x06))
            (if (= p 6) (w 1969 (logxor (i 1969) #x07))
              (if (= p 7) (w 1969 (logxor (i 1969) #x12))
                (f)))))))))
(w 2032 (logxor (i 2032) p))
(w 2078 (logxor (i 2078) p))
(w 2126 (logxor (i 2126) p))
(w 2176 (logxor (i 2176) p))
(w 2228 (logxor (i 2228) p))
(w 2282 (logxor (i 2282) p))
(w 2338 (logxor (i 2338) p))
(w 2396 (logxor (i 2396) p))
(e)
(p)
