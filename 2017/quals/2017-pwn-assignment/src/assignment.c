/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



#include "objects.h"
#include "str.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define END 			0
#define NAME			1
#define INTEGER			2
#define STRING			3
#define PERIOD			4
#define EQUALS			5
#define PLUS			6
#define INVALID			7

struct token {
  int type;
  // Inclusive exclusive.
  int start, end;
};

int isWhiteSpace(char c) {
  return c == ' ' || c == '\t' || c == '\n';
}

int isAlpha(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

int isDigit(char c) {
  return c >= '0' && c <= '9';
}

// We can create negative numbers by entering large postives.
long long strToInt(char *line, int length) {
  long long v = 0;
  int i;
  for (i = 0; i < length; i++) {
    v *= 10;
    v += line[i] - '0';
  }
  return v;
}

void getToken(Str line, int start, struct token* token) {
  int i = start;
  if (i == line->length) {
    token->type = END;
    return;
  }
  token->start = i;
  if (isAlpha(line->data[i])) {
    token->type = NAME;
    token->end = i + 1;
  } else if (isDigit(line->data[i])) {
    token->type = INTEGER;
    for (; i < line->length && isDigit(line->data[i]); i++);
    token->end = i;
  } else if (line->data[i] == '"') {
    token->type = STRING;
    for (i++; i < line->length && line->data[i] != '"'; i++);
    token->end = i + 1;
    if (i == line->length) {
      token->type = INVALID;
    }
  } else if (line->data[i] == '.') {
    token->type = PERIOD;
    token->end = i + 1;
  } else if (line->data[i] == '=') {
    token->type = EQUALS;
    token->end = i + 1;
  } else if (line->data[i] == '+') {
    token->type = PLUS;
    token->end = i + 1;
  } else {
    token->type = INVALID;
    token->end = i + 1;
  }
}

// This gets the next token, but will continue reading names until the end of them.
void getTokenWithNames(Str line, int start, struct token* token) {
  getToken(line, start, token);
  if (token->type != NAME) {
    if (token->type == PERIOD) {
      token->type = INVALID;
    }
    return;
  }
  int startP = token->start;
  int end = token->end;
  getToken(line, end, token);
  while (token->type == PERIOD) {
    end = token->end;
    getToken(line, end, token);
    // If there is a period, it must have a name after.
    if (token->type != NAME) {
      token->type = INVALID;
      return;
    }
    end = token->end;
    getToken(line, end, token);
  }
  token->type = NAME;
  token->start = startP;
  token->end = end;
}

// Returns if the given token is an entity (such as a name, integer or string).
int isEntityToken(struct token* token) {
  return token->type == NAME || token->type == INTEGER || token->type == STRING;
}

Object dereferenceAllButEnd(char *line, struct token* token, int shouldCreate) {
  int i;
  Object cur = NULL;
  for (i = token->start; i < token->end - 2; i += 2) {
    cur = createFromName(line[i], cur, shouldCreate);
    if (cur == NULL) {
      return NULL;
    }
  }
  return cur;
}

Object createObjectForToken(char *line, struct token* token) {
  Object o = NULL;
  switch (token->type) {
    case INTEGER:
      o = createFromInt(strToInt(&line[token->start], token->end - token->start));
      break;
    case STRING:
      o = createFromString(&line[token->start + 1], token->end - token->start - 2);
      break;
    case NAME:
      o = dereferenceAllButEnd(line, token, FALSE);
      if (o == NULL && token->end - token->start > 1) {
        return NULL;
      }
      o = createFromName(line[token->end - 1], o, FALSE);
      break;
  }
  return o;
}

void handlePrint(char *line, struct token* toPrint) {
  Object o = createObjectForToken(line, toPrint);
  if (o == NULL) {
    printf ("Object not found\n");
  } else {
    printObject(o);
  }
}

void handleAssign(char *line, struct token* leftSide, struct token* rightSide) {
  Object lhs = dereferenceAllButEnd(line, leftSide, TRUE);
  Object rhs = createObjectForToken(line, rightSide);
  if (rhs == NULL) {
    printf ("Object not found\n");
    return;
  }
  assignObject(lhs, line[leftSide->end - 1], rhs);
}

void handleAddAndAssign(char *line, struct token* leftSide, struct token* firstAdd, struct token* secondAdd) {
  Object lhs = dereferenceAllButEnd(line, leftSide, TRUE);
  Object add1 = createObjectForToken(line, firstAdd);
  Object add2 = createObjectForToken(line, secondAdd);
  if (add1 == NULL || add2 == NULL) {
    printf ("Object not found\n");
    return;
  }
  addObject(lhs, line[leftSide->end - 1], add1, add2);
}

void processLine(Str line) {
  // There are three cases:
  // 1) {name|integer|string}
  // 2) {name} = {name|integer|string}
  // 3) {name} = {name|integer|string} + {name|integer|string}
  struct token initialToken;
  getTokenWithNames(line, 0, &initialToken);
  if (!isEntityToken(&initialToken)) {
    if (initialToken.type != END) {
      printf("Bad token: %d-%d\n", initialToken.start, initialToken.end);
    }
    return;
  }
  struct token operator;
  getTokenWithNames(line, initialToken.end, &operator);
  // Case 1.
  if (operator.type == END) {
    // We should just print it out.
    handlePrint(line->data, &initialToken);
    return;
  }
  if (operator.type != EQUALS) {
    printf("Invalid operator: %d-%d\n", operator.start, operator.end);
    return;
  }
  if (initialToken.type != NAME) {
    printf("Can only assign to variable\n");
    return;
  }
  struct token firstPart;
  getTokenWithNames(line, operator.end, &firstPart);
  if (!isEntityToken(&firstPart)) {
    if (firstPart.type == END) {
      printf("Need something to assign\n");
    } else {
      printf("Bad token after equals: %d-%d\n", firstPart.start, firstPart.end);
    }
    return;
  }

  struct token potentialOp;
  getTokenWithNames(line, firstPart.end, &potentialOp);
  // Case 2.
  if (potentialOp.type == END) {
    handleAssign(line->data, &initialToken, &firstPart);
    return;
  }
  if (potentialOp.type != PLUS) {
    printf("Invalid operator: %d-%d\n", potentialOp.start, potentialOp.end);
    return;
  }
  struct token secondPart;
  getTokenWithNames(line, potentialOp.end, &secondPart);
  if (!isEntityToken(&secondPart)) {
    if (secondPart.type == END) {
      printf("Need something to add\n");
    } else {
      printf("Bad token after plus: %d-%d\n", secondPart.start, secondPart.end);
    }
    return;
  }
  // Case 3.
  handleAddAndAssign(line->data, &initialToken, &firstPart, &secondPart);
}

void readLine(Str s, int maxSize) {
  int i;
  for (i = 0; i < maxSize; i++) {
    if (read(0, &s->data[i], 1) <= 0) {
      printf("Failed reading\n");
      exit(1);
    }
    if (s->data[i] == '\n') {
      break;
    }
  }
  s->length = i;
}

int main() {
  struct str s;
  char buf[512];
  s.data = buf;
  while (1) {
    printf ("> ");
    fflush(stdout);
    readLine(&s, 512);
    processLine(&s);
  }
  return 0;
}
