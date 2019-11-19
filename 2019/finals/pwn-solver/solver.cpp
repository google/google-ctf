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

#include <stdlib.h>
#include <math.h>
#include <string.h>

#include <iostream>
#include <stdexcept>
#include <sstream>

#include "solver.h"


#define DEBUG 1


#ifdef DEBUG
#define dbg_print(x) std::cout << "[DEBUG] " << x << '\n';
#else
#define dbg_print(x)
#endif


int read_int(std::string strval) {
  std::string::size_type sz;
  int intval = 0;
  try {
    intval = std::stoi(strval);
  } catch (std::invalid_argument&) {
    std::cout << "[ERROR] Value entered wasn't an integer\n";
    exit(EXIT_FAILURE);
  }
  return intval;
}


void read_matrix(Matrix* m) {
  std::cout << "Enter your matrix:\n";
  for (int i = 0; i < m->n_rows; ++i) {
    std::string row;
    std::getline(std::cin, row);
    std::stringstream ss(row);
    double tmp;
    int col_cnt = 0;

    while (ss >> tmp) {
      m->add(i, col_cnt, tmp);
      col_cnt++;
      if (col_cnt == m->n_cols) break;
    }

  }
}


int read_number_of_unknowns() {
  std::string row;
  std::cout << "Enter number of unknown variables: ";
  std::getline(std::cin, row);
  int n_vars = read_int(row);
  return n_vars;
}


void print_solution(solution_set_t* s) {
  std::cout << "Reals: [ ";
  for (int i = 0; i < s->n; ++i) {
    std::cout << s->x_real[i] << " ";
  }
  std::cout << "]\nIntegers: [ ";

  for (int i = 0; i < s->n; ++i) {
    std::cout << s->x_int[i] << " ";
  }

  std::cout << "]\n\n";
}


Matrix::Matrix(int n_rows, int n_cols) {
  this->m = new double*[n_rows];
  for (int i = 0; i < n_rows; ++i) {
    this->m[i] = new double[n_cols];
  }
  this->n_rows = n_rows;
  this->n_cols = n_cols;
}


Matrix::~Matrix() {
  for (int i = 0; i < this->n_rows; ++i) {
    delete[] this->m[i];
  }
  delete[] this->m;
}


void Matrix::add(int row, int col, double value) {
  this->m[row][col] = value;
}


double Matrix::get(int row, int col) {
  return this->m[row][col];
}


void Matrix::swapRows(int src, int dst) {
  for (int i = 0; i < this->n_cols; ++i) {
    double tmp = this->m[src][i];
    this->m[src][i] = this->m[dst][i];
    this->m[dst][i] = tmp;
  }
}


void Matrix::multiplyAndSubtract(int src, double multiplier, int dst) {
  for (int i = 0; i < this->n_cols; ++i) {
    this->m[dst][i] -= multiplier * this->m[src][i];
  }
}


void Matrix::display() {
  for (int i = 0; i < this->n_rows; ++i) {
    for (int j = 0; j < this->n_cols; ++j) {
      std::cout << this->m[i][j] << " ";
    }
    std::cout << '\n';
  }
}


void Solver::addMatrix(Matrix* m) {
  this->m = m;
  this->n_vars = m->n_rows;
  this->hashval = this->doHash(m);

  dbg_print("hashval = 0x" << std::hex << this->hashval);

}


void Solver::partialPivot() {
  Matrix* m = this->m;
  for (int i = 0; i < m->n_rows-1; ++i) {
    for (int j = i+1; j < m->n_rows; ++j) {
      if (abs(m->get(i, i)) < abs(m->get(j, i))) {
        m->swapRows(i, j);
      }
    }
  }
}


void Solver::gaussElimination() {
  Matrix* m = this->m;
  for (int i = 0; i < m->n_rows-1; ++i) {
    for (int j = i+1; j < m->n_rows; ++j) {
      double ratio = m->get(j, i) / m->get(i, i);
      m->multiplyAndSubtract(i, ratio, j);
    }
  }
}


bool Solver::findRoots(double* x) {
  for (int i = this->m->n_rows-1; i >= 0; --i) {
    x[i] = this->m->get(i, this->m->n_cols-1);

    for (int j = i + 1; j < this->m->n_cols; ++j) {
      x[i] -= this->m->get(i,j) * x[j];
    }

    if (this->m->get(i,i) == 0) {
      return false;
    }

    x[i] /= this->m->get(i,i);
  }


  return true;
}

bool Solver::solve() {
  std::cout << "Solving the matrix:\n";
  // These two a necessary for at least one magic gadget in libc-2.24 to work
  asm("xor %r13, %r13");
  asm("xor %r12, %r12");
  this->m->display();
  std::cout << '\n';
  this->partialPivot();
  this->gaussElimination();

  this->x = (double *)malloc(sizeof(double) * this->n_vars);

  dbg_print("x @ 0x" << std::hex << (uint64_t)this->x);

  bool found = this->findRoots(this->x);

  return found;
}


solution_set_t* Solver::getSolution() {
  solution_set_t* s = (solution_set_t *)malloc(sizeof(solution_set_t));

  int64_t* x_int = (int64_t *)malloc(this->n_vars * sizeof(int64_t));

  dbg_print("x_int @ 0x" << std::hex <<  (uint64_t)x_int);

  for (int i = 0; i < this->n_vars; ++i) {
    x_int[i] = (int64_t)this->x[i];
  }

  s->x_int = x_int;
  s->x_real = this->x;
  s->n = this->n_vars;

  this->cache[this->hashval] = s;

  return s;
}


uint64_t Solver::doHash(Matrix *m) {
  uint64_t hashval = 0;
  for (int i = 0; i < m->n_rows; ++i) {
    for (int j = 0; j < m->n_cols; ++j) {
      hashval += (uint64_t)m->get(i,j) * 2654435761;
    }
  }
  return hashval;
}


bool Solver::isCached(Matrix *m) {
  return this->cache.find(this->doHash(m)) != this->cache.end();
}


solution_set_t* Solver::getCached(Matrix *m) {
  return this->cache[this->doHash(m)];
}


bool Solver::validateSolution(Matrix* mat, solution_set_t* s) {
  for (int i = 0; i < mat->n_rows; ++i) {
    double y = 0;
    for (int j = 0; j < mat->n_cols-1; ++j) {
      y += s->x_real[j] * mat->get(i, j);
    }

    if (y != mat->get(i, mat->n_cols-1)) {
      return false;
    }
  }

  return true;
}


int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  std::cout.precision(17);
  std::cout << "\nWelcome to Unstable Solver!\n";

  Solver* solver = new Solver();

  for(int i = 0; i < 5; i++) {

    dbg_print("solver @ 0x" << std::hex << (uint64_t)solver);

    int n_vars = read_number_of_unknowns();
    Matrix* m = new Matrix(n_vars, n_vars+1);

    dbg_print("m @ 0x" << std::hex << (uint64_t)m);

    read_matrix(m);

    if (solver->isCached(m) == false) {
      std::cout << "New matrix, preparing to solve\n";
      solver->addMatrix(m);
    } else {
      std::cout << "Restoring cached solution\n";
      solution_set_t* s = solver->getCached(m);
      if (solver->validateSolution(m, s)) {
        print_solution(s);
        continue;
      }
    }


    bool res = solver->solve();

    delete m;

    if (res == false) {
      std::cout << "Can't find solutions\n";
      continue;
    }

    solution_set_t* s = solver->getSolution();

    dbg_print("s @ 0x" << std::hex << (uint64_t)s);

    print_solution(s);

  }

  std::cout << "Bye!\n";
}
