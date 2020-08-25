// Copyright 2020 Google LLC
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

int check_device();

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
  int retval;

  const char* pUsername;
  retval = pam_get_user(pamh, &pUsername, "Username: ");
  if (retval != PAM_SUCCESS) {
    return retval;
  }

  if (strcmp(pUsername, "root") != 0) {
    // This shall only apply to root
    return PAM_PERM_DENIED;
  }

  fprintf(stderr, "Password: ");

  if (check_device() != 1) {
    fprintf(stderr, "Wrong username or password");
    return PAM_PERM_DENIED;
  }

  fprintf(stderr, "\n\nWelcome %s\n", pUsername);

  return PAM_SUCCESS;
}

int check_device() {
  FILE *fp;
  char buf[2]; // Device will only ever emit "1" (success) or "0" (fail)

  fp = fopen("/dev/chck", "r");
  fgets(buf, 2, (FILE*)fp);
  fclose(fp);

  return atoi(buf);
}
