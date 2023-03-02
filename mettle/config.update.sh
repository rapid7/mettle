#!/bin/sh
# This updates config.* files based on instructions at
# https://www.gnu.org/software/gettext/manual/html_node/config_002eguess.html
curl 'https://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess;hb=HEAD' > config.guess
curl 'https://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.sub;hb=HEAD' > config.sub
