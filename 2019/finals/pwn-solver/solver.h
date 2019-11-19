/*
Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdint.h>
#include <map>

#define SOL_ALL 1
#define SOL_INT 2

class Matrix {
 public:
  Matrix(int n_rows, int n_cols);
  ~Matrix();

  void add(int row, int col, double value);
  double get(int row, int col);
  void swapRows(int src, int dst);
  void multiplyAndSubtract(int src, double multiplier, int dst);
  virtual void display();

  int n_rows, n_cols;

 private:
  double** m;

};


typedef struct SolutionSet {
  int64_t* x_int;
  double* x_real;
  int n;
} solution_set_t;


class Solver {
 public:
  void addMatrix(Matrix* m);
  void partialPivot();
  void gaussElimination();
  bool findRoots(double* x);
  bool solve();
  solution_set_t* getSolution();
  uint64_t doHash(Matrix* m);
  bool isCached(Matrix* m);
  solution_set_t* getCached(Matrix* m);
  bool validateSolution(Matrix* m, solution_set_t* s);

 private:
  Matrix* m = NULL;
  double* x = NULL;
  int n_vars = 0;
  uint64_t hashval = 0;
  std::map<uint64_t, solution_set_t*> cache;

};
