#!/bin/sh
#
# This scripts takes the major and minor release numbers and adds
# local version information from the git version control system.
# Adapted from scripts/setlocalversion in the Linux kernel sources.
#
major=1
minor=3
extra=

usage() {
	echo "Usage: $0 [srctree]" >&2
	exit 1
}

srctree=.
if test $# -gt 0; then
	srctree=$1
	shift
fi
if test $# -gt 0 -o ! -d "$srctree"; then
	usage
fi

scm_version()
{
	cd "$srctree"

	# Check for git and a git repo.
	if test -d .git && head=`git rev-parse --verify --short HEAD 2>/dev/null`; then

		# If we are at a tagged commit (like "v2.6.30-rc6"), we ignore
		# it, because this version is defined in the top level Makefile.
		if [ -z "`git describe --exact-match 2>/dev/null`" ]; then

			# If we are past a tagged commit (like
			# "v2.6.30-rc5-302-g72357d5"), we pretty print it.
			if atag="`git describe 2>/dev/null`"; then
				echo "$atag" | awk -F- '{printf("-%05d-%s", $(NF-1),$(NF))}'

			# If we don't have a tag at all we print -g{commitish}.
			else
				printf '%s%s' -g $head
			fi
		fi

		# Update index only on r/w media
		[ -w . ] && git update-index --refresh --unmerged > /dev/null

		# Check for uncommitted changes
		if git diff-index --name-only HEAD | grep -qv "^scripts/package"; then
			printf '%s' -dirty
		fi

		# All done with git
		return
	fi
}

res="${major}.${minor}${extra}$(scm_version)"
echo "$res"
