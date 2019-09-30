### configure.ac					-*- Autoconf -*-
###
### Process this file with autoconf to produce a configure script.
###

AC_PREREQ(2.69)

## We want to get the version number from file 'VERSION' (rather than
## specifying the version info in 'configure.ac'.  Hence, we need a bit
## of M4 magic.  Note that M4 esyscmd has a trailing newline because the
## shell command output has one, hence the patsubst() trick.
m4_define([LC_VERSION],
          m4_bpatsubst(m4_esyscmd([cat VERSION]),
                       [\([0-9.]*\)\(\w\|\W\)*],
                       [\1]))
AC_INIT([linkja-crypto],[LC_VERSION],[https://linkja.github.io/],[linkja-crypto],[https://linkja.github.io/])
AM_INIT_AUTOMAKE([subdir-objects])

AC_PROG_CC
AM_PROG_CC_STDC
AC_C_CONST
AM_PROG_LIBTOOL

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
