/*
 * ntreg.c - NT Registry Hive access library
 *
 * 2008-mar: Type QWORD (XP/Vista and newer) now recognized
 * 2008-mar: Most functions accepting a path now also have a parameter specifying if
 *           the search should be exact or on first match basis
 * 2008-mar: Fixed bug which skipped first indirect index table when deleting keys,
 *           usually leading to endless loop when recursive deleting.
 * 2008-mar: Export to .reg file by Leo von Klenze, expanded a bit by me.
 * 2008-mar: 64 bit compatible patch by Mike Doty, via Alon Bar-Lev
 *           http://bugs.gentoo.org/show_bug.cgi?id=185411
 * 2007-sep: Verbosity/debug messages minor changes
 * 2007-apr: LGPL license.
 * 2004-aug: Deep indirect index support. NT351 support. Recursive delete.
 *           Debugged a lot in allocation routines. Still no expansion.
 * 2004-jan: Verbosity updates
 * 2003-jan: Allocation of new data, supports adding/deleting keys & stuff.
 *           Missing is expanding the file.
 * 2003-jan: Seems there may be garbage pages at end of file, not zero pages
 *           now stops enumerating at first non 'hbin' page.
 * 
 * NOTE: The API is not frozen. It can and will change every release.
 *
 *****
 *
 * NTREG - Window registry file reader / writer library
 * Copyright (c) 1997-2007 Petter Nordahl-Hagen.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * See file LGPL.txt for the full license.
 * 
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

#include "ntreg.h"
#define bzero(a, b)	memset(a, 0, b)
#define strncasecmp stricmp

/* Set to abort() and debug on more critical errors */
#define DOCORE 1

#define ZEROFILL      1  /* Fill blocks with zeroes when allocating and deallocating */
#define ZEROFILLONLOAD  0  /* Fill blocks marked as unused/deallocated with zeroes on load. FOR DEBUG */

const char ntreg_version[] = "ntreg lib routines, v0.94 080526, (c) Petter N Hagen";

const char *val_types[REG_MAX+1] = {
  "REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD",       /* 0 - 4 */
  "REG_DWORD_BIG_ENDIAN", "REG_LINK",                                     /* 5 - 6 */
  "REG_MULTI_SZ", "REG_RESOUCE_LIST", "REG_FULL_RES_DESC", "REG_RES_REQ", /* 7 - 10 */
  "REG_QWORD"                                                          /* 11     */
};

/* Utility routines */
char *str_dup( const char *str )
{
    char *str_new;

    if (!str)
        return 0 ;

    CREATE( str_new, char, strlen(str) + 1 );
    strcpy( str_new, str );
    return str_new;
}

int fmyinput(char *prmpt, char *ibuf, int maxlen)
{
   
   printf("%s",prmpt);
   
   fgets(ibuf,maxlen+1,stdin);
   
   ibuf[strlen(ibuf)-1] = 0;
   
   return(strlen(ibuf));
}

/* Print len number of hexbytes */

void hexprnt(char *s, unsigned char *bytes, int len)
{
int i;

   printf("%s",s);
   for (i = 0; i < len; i++) {
      printf("%02x ",bytes[i]);
   }
   printf("\n");
}

/* HexDump all or a part of some buffer */

void hexdump(char *hbuf, int start, int stop, int ascii)
{
   char c;
   int diff,i;
   
   while (start < stop ) {
      
      diff = stop - start;
      if (diff > 16) diff = 16;
      
      printf(":%05X  ",start);

      for (i = 0; i < diff; i++) {
	 printf("%02X ",(unsigned char)*(hbuf+start+i));
      }
      if (ascii) {
	for (i = diff; i < 16; i++) printf("   ");
	for (i = 0; i < diff; i++) {
	  c = *(hbuf+start+i);
	  printf("%c", isprint(c) ? c : '.');
	}
      }
      printf("\n");
      start += 16;
   }
}

/* General search routine, find something in something else */
int find_in_buf(char *buf, char *what, int sz, int len, int start)
{
   int i;
   
   for (; start < sz; start++) {
      for (i = 0; i < len; i++) {
	if (*(buf+start+i) != *(what+i)) break;
      }
      if (i == len) return(start);
   }
   return(0);
}

/* Get INTEGER from memory. This is probably low-endian specific? */
int get_int( char *array )
{
	return ((array[0]&0xff) + ((array[1]<<8)&0xff00) +
		   ((array[2]<<16)&0xff0000) +
		   ((array[3]<<24)&0xff000000));
}


/* Quick and dirty UNICODE to std. ascii */

void cheap_uni2ascii(char *src, char *dest, int l)
{
   
   for (; l > 0; l -=2) {
      *dest = *src;
      dest++; src +=2;
   }
   *dest = 0;
}


/* Quick and dirty ascii to unicode */

void cheap_ascii2uni(char *src, char *dest, int l)
{
   for (; l > 0; l--) {
      *dest++ = *src++;
      *dest++ = 0;

   }
}

void skipspace(char **c)
{
   while( **c == ' ' ) (*c)++;
}

int gethex(char **c)
{
   int value;
   
   skipspace(c);
   
   if (!(**c)) return(0);

   sscanf(*c,"%x",&value);

   while( **c != ' ' && (**c)) (*c)++;

   return(value);
}
   
/* Get a string of HEX bytes (space separated),
 * or if first char is ' get an ASCII string instead.
 */

int gethexorstr(char **c, char *wb)
{
   int l = 0;
   
   skipspace(c);
   
   if ( **c == '\'') {
      (*c)++;
      while ( **c ) {
	 *(wb++) = *((*c)++);
	 l++;
      }
   } else {
      do {
	 *(wb++) = gethex(c);
	 l++;
	 skipspace(c);
      } while ( **c );
   }
   return(l);
}

/* Simple buffer debugger, returns 1 if buffer dirty/edited */

int debugit(char *buf, int sz)
{
	return 0;
}


/* ========================================================================= */

/* The following routines are mostly for debugging, I used it
 * much during discovery. the -t command line option uses it,
 * also the 'st' and 's' from the editor & hexdebugger.
 * All offsets shown in these are unadjusted (ie you must add
 * headerpage (most often 0x1000) to get file offset)
 */

/* Parse the nk datablock
 * vofs = offset into struct (after size linkage)
 */
void parse_nk(struct hive *hdesc, int vofs, int blen)
{
  struct nk_key *key;
  int i;
  key = (struct nk_key *)(hdesc->buffer + vofs);
}

/* Parse the vk datablock
 * vofs = offset into struct (after size linkage)
 */
void parse_vk(struct hive *hdesc, int vofs, int blen)
{
  struct vk_key *key;
  int i;
}

/* Parse the sk datablock
 * Gee, this is the security info. Who cares? *evil grin*
 * vofs = offset into struct (after size linkage)
 */
void parse_sk(struct hive *hdesc, int vofs, int blen)
{
  struct sk_key *key;
}


/* Parse the lf datablock (>4.0 'nk' offsets lookuptable)
 * vofs = offset into struct (after size linkage)
 */
void parse_lf(struct hive *hdesc, int vofs, int blen)
{
  struct lf_key *key;
  int i;

}

/* Parse the lh datablock (WinXP offsets lookuptable)
 * vofs = offset into struct (after size linkage)
 * The hash is most likely a base 37 conversion of the name string
 */
void parse_lh(struct hive *hdesc, int vofs, int blen)
{
  struct lf_key *key;
  int i;

}


/* Parse the li datablock (3.x 'nk' offsets list)
 * vofs = offset into struct (after size linkage)
 */
void parse_li(struct hive *hdesc, int vofs, int blen)
{
  struct li_key *key;
  int i;

}

/* Parse the ri subindex-datablock
 * (Used to list li/lf/lh's when ~>500keys)
 * vofs = offset into struct (after size linkage)
 */
void parse_ri(struct hive *hdesc, int vofs, int blen)
{
  struct ri_key *key;
  int i;

}


/* Parse the datablock
 * vofs = offset into struct (after size linkage)
 */

int parse_block(struct hive *hdesc, int vofs,int verbose)
{
  unsigned short id;
  int seglen;

  seglen = get_int(hdesc->buffer+vofs);  


  
  if (seglen < 0) {
    seglen = -seglen;
    hdesc->usetot += seglen;
    hdesc->useblk++;
  } else {
    hdesc->unusetot += seglen;
    hdesc->unuseblk++;
#if ZEROFILLONLOAD
    bzero(hdesc->buffer+vofs+4,seglen-4);
#endif
  }

  vofs += 4;
  id = (*(hdesc->buffer + vofs)<<8) + *(hdesc->buffer+vofs+1);

  if (verbose) {
    switch (id) {
    case 0x6e6b: /* nk */
      parse_nk(hdesc, vofs, seglen);
      break;
    case 0x766b: /* vk */
      parse_vk(hdesc, vofs, seglen);
      break;
    case 0x6c66: /* lf */
      parse_lf(hdesc, vofs, seglen);
      break;
    case 0x6c68: /* lh */
      parse_lh(hdesc, vofs, seglen);
      break;
    case 0x6c69: /* li */
      parse_li(hdesc, vofs, seglen);
      break;
    case 0x736b: /* sk */
      parse_sk(hdesc, vofs, seglen);
      break;
    case 0x7269: /* ri */
      parse_ri(hdesc, vofs, seglen);
      break;
    default:
      break;
    }
  }
  return(seglen);
}

int find_page_start(struct hive *hdesc, int vofs)
{
  int r,prev;
  struct hbin_page *h;

  r = 0x1000;
  while (r < hdesc->size) {
    prev = r;
    h = (struct hbin_page *)(hdesc->buffer + r);
    if (h->id != 0x6E696268) return(0);
    if (h->ofs_next == 0) {
      return(0);
    }
    r += h->ofs_next;
    if (r > vofs) return (prev);
  }
  return(0);
}
#define FB_DEBUG 0

int find_free_blk(struct hive *hdesc, int pofs, int size)
{
  int vofs = pofs + 0x20;
  int seglen;
  struct hbin_page *p;
  
  p = (struct hbin_page *)(hdesc->buffer + pofs);

  while (vofs-pofs < (p->ofs_next - HBIN_ENDFILL)) {

    seglen = get_int(hdesc->buffer+vofs);  

    if (seglen == 0) {
      return(0);
    }
    
    if (seglen < 0) {
      seglen = -seglen;
    } else {
	if (seglen >= size) {
	  return(vofs);
	}
    }
    vofs += seglen;
  }
  return(0);
  
}

#undef FB_DEBUG

int find_free(struct hive *hdesc, int size)
{
  int r,blk;
  struct hbin_page *h;

  if (size & 7) size += (8 - (size & 7));

  r = 0x1000;
  while (r < hdesc->size) {
    h = (struct hbin_page *)(hdesc->buffer + r);
    if (h->id != 0x6E696268) return(0);
    if (h->ofs_next == 0) {
      return(0);
    }
    blk = find_free_blk(hdesc,r,size);
    if (blk) return (blk);
    r += h->ofs_next;
  }
  return(0);
}

int alloc_block(struct hive *hdesc, int ofs, int size)
{
  int pofs = 0;
  int blk = 0;
  int trail, trailsize, oldsz;

  if (hdesc->state & HMODE_NOALLOC) {
    return(0);
  }

  size += 4;
  if (size & 7) size += (8 - (size & 7));

  if (ofs) {
    pofs = find_page_start(hdesc,ofs);
    blk = find_free_blk(hdesc,pofs,size);
  }

  if (!blk) {
    blk = find_free(hdesc,size);
  }

  if (blk) {
    oldsz = get_int(hdesc->buffer+blk);
    trailsize = oldsz - size;

    if (trailsize == 4) {
      trailsize = 0;
      size += 4;
    }

 #if 1
    if (trailsize & 7) {
      trailsize -= (8 - (trailsize & 7));
      size += (8 - (trailsize & 7));
    }
    if (trailsize == 4) {
      trailsize = 0;
      size += 4;
    }
#endif
    *(int *)((hdesc->buffer)+blk) = -(size);

    hdesc->useblk++;
    hdesc->unuseblk--;
    hdesc->usetot += size;
    hdesc->unusetot -= size;

    if (trailsize) {
      trail = blk + size;

      *(int *)((hdesc->buffer)+trail) = (int)trailsize;

      hdesc->useblk++;    /* This will keep blockcount */
      hdesc->unuseblk--;
      hdesc->usetot += 4; /* But account for more linkage bytes */
      hdesc->unusetot -= 4;

    }  
    /* Clear the block data, makes it easier to debug */
#if ZEROFILL
    bzero( (void *)(hdesc->buffer+blk+4), size-4);
#endif

    hdesc->state |= HMODE_DIRTY;
    
    return(blk);
  } else {
    
  }
  return(0);
}


#define FB_DEBUG 0

int free_block(struct hive *hdesc, int blk)
{
  int pofs,vofs,seglen,prev,next,nextsz,prevsz,size;
  struct hbin_page *p;

  if (hdesc->state & HMODE_NOALLOC) {
    return(0);
  }

  size = get_int(hdesc->buffer+blk);
  if (size >= 0) {
    return(0);
  }
  size = -size;
  pofs = find_page_start(hdesc,blk);
  if (!pofs) return(0);

  p = (struct hbin_page *)(hdesc->buffer + pofs);
  vofs = pofs + 0x20;

  prevsz = -32;

  if (vofs != blk) {
    while (vofs-pofs < (p->ofs_next - HBIN_ENDFILL) ) {

      seglen = get_int(hdesc->buffer+vofs);  
      
      if (seglen == 0) {
	return(0);
      }
      
      if (seglen < 0) {
	seglen = -seglen;
      } 
      prev = vofs;
      vofs += seglen;
      if (vofs == blk) break;
    }
    
    if (vofs != blk) {
      return(0);
    }
    
    prevsz = get_int(hdesc->buffer+prev);
    
  }

  next = blk + size;

  nextsz = 0;
  if (next-pofs < (p->ofs_next - HBIN_ENDFILL) ) nextsz = get_int(hdesc->buffer+next);


  if ( nextsz > 0) {
    size += nextsz; 
    hdesc->useblk--;
    hdesc->usetot -= 4;
    hdesc->unusetot -= 4; 
  }

#if ZEROFILL
   bzero( (void *)(hdesc->buffer+blk), size);
#endif

  *(int *)((hdesc->buffer)+blk) = (int)size;
  hdesc->usetot -= size;
  hdesc->unusetot -= size;  /* FIXME !?!? */
  hdesc->unuseblk--;

  hdesc->state |= HMODE_DIRTY;
  if (prevsz > 0) {
    hdesc->usetot -= prevsz;
    hdesc->unusetot += prevsz;
    prevsz += size;
    /* And swallow current.. */
#if ZEROFILL
      bzero( (void *)(hdesc->buffer+prev), prevsz);
#endif
    *(int *)((hdesc->buffer)+prev) = (int)prevsz;
    hdesc->useblk--;
    return(prevsz);
  }
  return(size);
}

int ex_next_n(struct hive *hdesc, int nkofs, int *count, int *countri, struct ex_data *sptr)
{
  struct nk_key *key, *newnkkey;
  int newnkofs;
  struct lf_key *lfkey;
  struct li_key *likey;
  struct ri_key *rikey;


  if (!nkofs) return(-1);
  key = (struct nk_key *)(hdesc->buffer + nkofs);
  if (key->id != 0x6b6e) {
    return(-1);
  }

#define EXNDEBUG 0

  lfkey = (struct lf_key *)(hdesc->buffer + key->ofs_lf + 0x1004);
  rikey = (struct ri_key *)(hdesc->buffer + key->ofs_lf + 0x1004);

  if (rikey->id == 0x6972) {
    if (*countri < 0 || *countri >= rikey->no_lis) { 
      return(0);
    }
    likey = (struct li_key *)( hdesc->buffer + rikey->hash[*countri].ofs_li + 0x1004 ) ;
    if (likey->id == 0x696c) {
      newnkofs = likey->hash[*count].ofs_nk + 0x1000;
    } else {
      lfkey = (struct lf_key *)( hdesc->buffer + rikey->hash[*countri].ofs_li + 0x1004 ) ;
      newnkofs = lfkey->hash[*count].ofs_nk + 0x1000;
    }
    if (*count >= likey->no_keys-1) {
      (*countri)++; 
      (*count) = -1; 
    }
  } else {
    if (key->no_subkeys <= 0 || *count >= key->no_subkeys) {
      return(0);
    }
    if (lfkey->id == 0x696c) {
      likey = (struct li_key *)(hdesc->buffer + key->ofs_lf + 0x1004);
      newnkofs = likey->hash[*count].ofs_nk + 0x1000;
    } else {
      newnkofs = lfkey->hash[*count].ofs_nk + 0x1000;
    }
  }

  sptr->nkoffs = newnkofs;
  newnkkey = (struct nk_key *)(hdesc->buffer + newnkofs + 4);
  sptr->nk = newnkkey;

  if (newnkkey->id != 0x6b6e) {
    return(-1);
  } else {
    if (newnkkey->len_name <= 0) {
    } else {
      sptr->name = (char *)malloc(newnkkey->len_name+1);
      if (!sptr->name) {
	abort();
      }
      strncpy(sptr->name,newnkkey->keyname,newnkkey->len_name);
      sptr->name[newnkkey->len_name] = 0;
    }
  } /* if */
  (*count)++;
  return(1);
  /*  return( *count <= key->no_subkeys); */
}

int ex_next_v(struct hive *hdesc, int nkofs, int *count, struct vex_data *sptr)
{
  struct nk_key *key /* , *newnkkey */ ;
  int vkofs,vlistofs;
  int *vlistkey;
  struct vk_key *vkkey;


  if (!nkofs) return(-1);
  key = (struct nk_key *)(hdesc->buffer + nkofs);
  if (key->id != 0x6b6e) {
    return(-1);
  }

  if (key->no_values <= 0 || *count >= key->no_values) {
    return(0);
  }

  vlistofs = key->ofs_vallist + 0x1004;
  vlistkey = (int *)(hdesc->buffer + vlistofs);

  vkofs = vlistkey[*count] + 0x1004;
  vkkey = (struct vk_key *)(hdesc->buffer + vkofs);
  if (vkkey->id != 0x6b76) {
    return(-1);
  }

  sptr->vk = vkkey;
  sptr->vkoffs = vkofs;
  sptr->name = 0;
  sptr->size = (vkkey->len_data & 0x7fffffff);

  if (vkkey->len_name >0) {
    CREATE(sptr->name,char,vkkey->len_name+1);
    memcpy(sptr->name,vkkey->keyname,vkkey->len_name);
    sptr->name[vkkey->len_name] = 0;
  } else {
    sptr->name = str_dup("@");
  }

  sptr->type = vkkey->val_type;
  if (sptr->size) {
    if (vkkey->val_type == REG_DWORD) {
      if (vkkey->len_data & 0x80000000) {
	sptr->val = (int)(vkkey->ofs_data);
      }
    }
  } else if (vkkey->len_data == 0x80000000) { 
    sptr->val = (int)(vkkey->val_type);
    sptr->size = 4;
    sptr->type = REG_DWORD;
  } else {
    sptr->val = 0;
    sptr->size = 0;
  }

  (*count)++;
  return( *count <= key->no_values );
}


int get_abs_path(struct hive *hdesc, int nkofs, char *path, int maxlen)
{
  /* int newnkofs; */
  struct nk_key *key;
  char tmp[ABSPATHLEN+1];

  maxlen = (maxlen < ABSPATHLEN ? maxlen : ABSPATHLEN);

  key = (struct nk_key *)(hdesc->buffer + nkofs);
  
  if (key->id != 0x6b6e) {
    return(0);
  }

  if (key->type == KEY_ROOT) {   /* We're at the root */
    return(strlen(path));
  }

  strncpy(tmp,path,ABSPATHLEN-1);

  if ( (strlen(path) + key->len_name) >= maxlen-6) {
    _snprintf(path,maxlen,"(...)%s",tmp);
    return(strlen(path));   /* Stop trace when string exhausted */
  }
  *path = '\\';
  memcpy(path+1,key->keyname,key->len_name);
  strncpy(path+key->len_name+1,tmp,maxlen);
  return(get_abs_path(hdesc, key->ofs_parent+0x1004, path, maxlen)); /* go back one more */
}


int vlist_find(struct hive *hdesc, int vlistofs, int numval, char *name, int type)
{
  struct vk_key *vkkey;
  int i,vkofs,len;
  int32_t *vlistkey;

  len = strlen(name);
  vlistkey = (int32_t *)(hdesc->buffer + vlistofs);

  for (i = 0; i < numval; i++) {
    vkofs = vlistkey[i] + 0x1004;
    vkkey = (struct vk_key *)(hdesc->buffer + vkofs);
    if (vkkey->len_name == 0 && *name == '@') { /* @ is alias for nameless value */
      return(i);
    }
    if ( !(type & TPF_EXACT) || vkkey->len_name == len ) {
      if (!strncmp(name, vkkey->keyname, len)) { /* name match? */
	return(i);
      }
    }
  }
  return(-1);

}


int trav_path(struct hive *hdesc, int vofs, char *path, int type)
{
  struct nk_key *key, *newnkkey;
  struct lf_key *lfkey;
  struct li_key *likey;
  struct ri_key *rikey;

  int32_t *vlistkey;
  int newnkofs, plen, i, lfofs, vlistofs, adjust, r, ricnt, subs;
  char *buf;
  char part[ABSPATHLEN+1];
  char *partptr;

  if (!hdesc) return(0);
  buf = hdesc->buffer;

  if (!vofs) vofs = hdesc->rootofs+4;     /* No current key given , so start at root */

  if (*path == '\\' && *(path+1) != '\\') {      /* Start from root if path starts with \ */
    path++;
    vofs = hdesc->rootofs+4;
  }

  key = (struct nk_key *)(buf + vofs);

  if (key->id != 0x6b6e) {
    return(0);
  }

  partptr = part;
  for(plen = 0; path[plen] && (path[plen] != '\\' || path[plen+1] == '\\'); plen++) {
    if (path[plen] == '\\' && path[plen+1] == '\\') plen++; /* Skip one if double */
    *partptr++ = path[plen];
  }
  *partptr = '\0';

  adjust = (path[plen] == '\\' ) ? 1 : 0;
  if (!plen) return(vofs-4);     /* Path has no lenght - we're there! */
  if ( (plen == 1) && (*path == '.') && !(type & TPF_EXACT)) {     /* Handle '.' current dir */
    return(trav_path(hdesc,vofs,path+plen+adjust,type));
  }
  if ( !(type & TPF_EXACT) && (plen == 2) && !strncmp("..",path,2) ) { /* Get parent key */
    newnkofs = key->ofs_parent + 0x1004;
    return(trav_path(hdesc, (key->type == KEY_ROOT ? vofs : newnkofs), path+plen+adjust, type));
  }

  if (!path[plen] && (type & TPF_VK) && key->no_values) {   
    vlistofs = key->ofs_vallist + 0x1004;
    vlistkey = (int32_t *)(buf + vlistofs);
    i = vlist_find(hdesc, vlistofs, key->no_values, part, type);
    if (i != -1) {
      return(vlistkey[i] + 0x1000);
    }
  }

  if (key->no_subkeys > 0) {    /* If it has subkeys, loop through the hash */
    lfofs = key->ofs_lf + 0x1004;    /* lf (hash) record */
    lfkey = (struct lf_key *)(buf + lfofs);

    if (lfkey->id == 0x6972) { /* ri struct need special parsing */
      rikey = (struct ri_key *)lfkey;
      ricnt = rikey->no_lis;
      r = 0;
      likey = (struct li_key *)( hdesc->buffer + rikey->hash[r].ofs_li + 0x1004 ) ;
      subs = likey->no_keys;
      if (likey->id != 0x696c) {  /* Bwah, not li anyway, XP uses lh usually which is actually smarter */
	lfkey = (struct lf_key *)( hdesc->buffer + rikey->hash[r].ofs_li + 0x1004 ) ;
	likey = NULL;
      }
    } else {
      if (lfkey->id == 0x696c) { /* li? */
	likey = (struct li_key *)(buf + lfofs);
      } else {
	likey = NULL;
      }
      ricnt = 0; r = 0; subs = key->no_subkeys;
    }

    do {
      for(i = 0; i < subs; i++) {
	if (likey) newnkofs = likey->hash[i].ofs_nk + 0x1004;
	else newnkofs = lfkey->hash[i].ofs_nk + 0x1004;
	newnkkey = (struct nk_key *)(buf + newnkofs);
	if (newnkkey->id != 0x6b6e) {
	} else {
	  if (newnkkey->len_name <= 0) {
	  } else {
	    if (!strncmp(part,newnkkey->keyname,plen)) {
	      return(trav_path(hdesc, newnkofs, path+plen+adjust, type));
	    }
	  }
	} /* if id OK */
      } /* hash loop */
      r++;
      if (ricnt && r < ricnt) {
	newnkofs = rikey->hash[r].ofs_li;
	likey = (struct li_key *)( hdesc->buffer + newnkofs + 0x1004 ) ;
	subs = likey->no_keys;
	if (likey->id != 0x696c) {  /* Bwah, not li anyway, XP uses lh usually which is actually smarter */
	  lfkey = (struct lf_key *)( hdesc->buffer + rikey->hash[r].ofs_li + 0x1004 ) ;
	  likey = NULL;
	}
      }
    } while (r < ricnt && ricnt);

  } /* if subkeys */
  /* Not found */
  return(0);
}



void nk_ls(struct hive *hdesc, char *path, int vofs, int type)
{
  
}

/* Get the type of a value */
int get_val_type(struct hive *hdesc, int vofs, char *path, int exact)
{
  struct vk_key *vkkey;
  int vkofs;

  vkofs = trav_path(hdesc, vofs,path,exact | TPF_VK);
  if (!vkofs) {
    return -1;
  }
  vkofs +=4;
  vkkey = (struct vk_key *)(hdesc->buffer + vkofs);
#if 0
  if (vkkey->len_data & 0x80000000) return(REG_DWORD); /* Special case of INLINE storage */
#endif
  return(vkkey->val_type);
}


/* Get len of a value, given current key + path */
int get_val_len(struct hive *hdesc, int vofs, char *path, int exact)
{
  struct vk_key *vkkey;
  int vkofs;
  int len;

  vkofs = trav_path(hdesc, vofs,path,exact | TPF_VK);
  if (!vkofs) {
    return -1;
  }
  vkofs +=4;
  vkkey = (struct vk_key *)(hdesc->buffer + vkofs);

  len = vkkey->len_data & 0x7fffffff;

  if ( vkkey->len_data == 0x80000000 ) {  /* Special inline case, return size of 4 (dword) */
    len = 4;
  }

  return(len);
}


void *get_val_data(struct hive *hdesc, int vofs, char *path, int val_type, int exact)
{
  struct vk_key *vkkey;
  int vkofs;

  vkofs = trav_path(hdesc,vofs,path,exact | TPF_VK);
  if (!vkofs) {
    return NULL;
  }
  vkofs +=4;
  vkkey = (struct vk_key *)(hdesc->buffer + vkofs);


  if (vkkey->len_data == 0) return NULL;
  if (vkkey->len_data == 0x80000000) {  /* Special inline case (len = 0x80000000) */
    return(&vkkey->val_type); /* Data (4 bytes?) in type field */
  }    

  if (val_type && vkkey->val_type && (vkkey->val_type) != val_type) {
    return NULL;
  }


  if (vkkey->len_data & 0x80000000) return(&vkkey->ofs_data);
  /* Normal return, return data pointer */
  return(hdesc->buffer + vkkey->ofs_data + 0x1004);
}


struct keyval *get_val2buf(struct hive *hdesc, struct keyval *kv,
			   int vofs, char *path, int type, int exact )
{
  int l;
  struct keyval *kr;
  void *keydataptr;

  l = get_val_len(hdesc, vofs, path, exact);
  if (l == -1) return(NULL);  /* error */
  if (kv && (kv->len < l)) return(NULL); /* Check for overflow of supplied buffer */

  keydataptr = get_val_data(hdesc, vofs, path, type, exact);
  if (kv) {
    kr = kv;
  } else {
    ALLOC(kr,1,l+sizeof(int)+4);
  }

  kr->len = l;
  memcpy(&(kr->data), keydataptr, l);

  return(kr);
}

/* DWORDs are so common that I make a small function to get it easily */

int get_dword(struct hive *hdesc, int vofs, char *path, int exact)
{
  struct keyval *v;
  int dword;

  v = get_val2buf(hdesc, NULL, vofs, path, REG_DWORD, exact | TPF_VK);
  if (!v) return(-1); /* well... -1 COULD BE THE STORED VALUE TOO */

  dword = (int)v->data;

  FREE(v);

  return(dword);
  
}

int fill_block(struct hive *hdesc, int ofs, void *data, int size)
{
  int blksize;

  blksize = get_int(hdesc->buffer + ofs);
  blksize = -blksize;
  if (blksize < size) {
  }

  memcpy(hdesc->buffer + ofs + 4, data, size);
  return(0);
}


int free_val_data(struct hive *hdesc, int vofs, char *path, int exact)
{
  struct vk_key *vkkey;
  int vkofs, inl;

  vkofs = trav_path(hdesc,vofs,path,1);
  if (!vkofs) {
    return 0;
  }
  vkofs +=4;
  vkkey = (struct vk_key *)(hdesc->buffer + vkofs);

  inl = (vkkey->len_data & 0x80000000);

  if (!inl) {
    free_block(hdesc, vkkey->ofs_data + 0x1000);
  }
  vkkey->len_data = 0;
  vkkey->ofs_data = 0;

  return(vkofs);

}

int alloc_val_data(struct hive *hdesc, int vofs, char *path, int size,int exact)
{
  struct vk_key *vkkey;
  int vkofs, len;
  int datablk;

  vkofs = trav_path(hdesc,vofs,path,1);
  if (!vkofs) {
    return (0);
  }

  vkofs +=4;
  vkkey = (struct vk_key *)(hdesc->buffer + vkofs);

  /* Allocate space for new data */
  datablk = alloc_block(hdesc, vkofs, size);
  if (!datablk) return(0);

  len = vkkey->len_data & 0x7fffffff;

  /* Then we dealloc if something was there before */
  if (len) free_val_data(hdesc,vofs,path,exact);

  /* Link in new datablock */
  vkkey->ofs_data = datablk - 0x1000;
  vkkey->len_data = size;

  return(datablk + 4);
}


struct vk_key *add_value(struct hive *hdesc, int nkofs, char *name, int type)
{
  struct nk_key *nk;
  int oldvlist = 0, newvlist, newvkofs;
  struct vk_key *newvkkey;
  char *blank="";

  if (!name || !*name) return(NULL);


  nk = (struct nk_key *)(hdesc->buffer + nkofs);
  if (nk->id != 0x6b6e) {
    return(NULL);
  }

  if (trav_path(hdesc, nkofs, name, 1)) {
    return(NULL);
  }

  if (!strcmp(name,"@")) name = blank;
 
  if (nk->no_values) oldvlist = nk->ofs_vallist;

  newvlist = alloc_block(hdesc, nkofs, nk->no_values * 4 + 4);
  if (!newvlist) {
    return(NULL);
  }
  if (oldvlist) {   /* Copy old data if any */
    memcpy(hdesc->buffer + newvlist + 4, hdesc->buffer + oldvlist + 0x1004, nk->no_values * 4 + 4);
  }

  /* Allocate value descriptor including its name */
  newvkofs = alloc_block(hdesc, newvlist, sizeof(struct vk_key) + strlen(name));
  if (!newvkofs) {
    free_block(hdesc, newvlist);
    return(NULL);
  }

  /* Success, now fill in the metadata */

  newvkkey = (struct vk_key *)(hdesc->buffer + newvkofs + 4);

  /* Add pointer in value list */
  *(int *)(hdesc->buffer + newvlist + 4 + (nk->no_values * 4)) = newvkofs - 0x1000;

  /* Fill in vk struct */
  newvkkey->id = 0x6b76;
  newvkkey->len_name = strlen(name);
  if (type == REG_DWORD || type == REG_DWORD_BIG_ENDIAN) {
    newvkkey->len_data = 0x80000004;  /* Prime the DWORD inline stuff */
  } else {
    newvkkey->len_data = 0x00000000;
  }
  newvkkey->ofs_data = 0;
  newvkkey->val_type = type;
  newvkkey->flag     = 1;   /* Don't really know what this is */
  newvkkey->dummy1   = 0;
  strcpy((char *)&newvkkey->keyname, name);  /* And copy name */

  /* Finally update the key and free the old valuelist */
  nk->no_values++;
  nk->ofs_vallist = newvlist - 0x1000;
  if (oldvlist) free_block(hdesc,oldvlist + 0x1000);

  return(newvkkey);

}

void del_vk(struct hive *hdesc, int vkofs)
{
  struct vk_key *vk;

  vk = (struct vk_key *)(hdesc->buffer + vkofs);
  if (vk->id != 0x6b76) {
    return;
  }
  
  if ( !(vk->len_data & 0x80000000) && vk->ofs_data) {
    free_block(hdesc, vk->ofs_data + 0x1000);
  }

  free_block(hdesc, vkofs - 4);
}


void del_allvalues(struct hive *hdesc, int nkofs)
{
  int vlistofs, o, vkofs;
  int32_t *vlistkey;
  struct nk_key *nk;

  nk = (struct nk_key *)(hdesc->buffer + nkofs);
  if (nk->id != 0x6b6e) {
    return;
  }

  if (!nk->no_values) {
    return;
  }

  vlistofs = nk->ofs_vallist + 0x1004;
  vlistkey = (int32_t *)(hdesc->buffer + vlistofs);

  /* Loop through index and delete all vk's */
  for (o = 0; o < nk->no_values; o++) {
    vkofs = vlistkey[o] + 0x1004;
    del_vk(hdesc, vkofs);
  }

  /* Then zap the index, and update nk */
  free_block(hdesc, vlistofs-4);
  nk->ofs_vallist = -1;
  nk->no_values = 0;
}


int del_value(struct hive *hdesc, int nkofs, char *name, int exact)
{
  int vlistofs, slot, o, n, vkofs, newlistofs;
  int32_t *vlistkey, *tmplist, *newlistkey;
  struct nk_key *nk;
  char *blank="";

  if (!name || !*name) return(1);

  if (!strcmp(name,"@")) name = blank;

  nk = (struct nk_key *)(hdesc->buffer + nkofs);
  if (nk->id != 0x6b6e) {
    return(1);
  }

  if (!nk->no_values) {
    return(1);
  }

  vlistofs = nk->ofs_vallist + 0x1004;
  vlistkey = (int32_t *)(hdesc->buffer + vlistofs);

  slot = vlist_find(hdesc, vlistofs, nk->no_values, name, TPF_VK);

  if (slot == -1) {
    return(1);
  }

  /* Delete vk and data */
  vkofs = vlistkey[slot] + 0x1004;
  del_vk(hdesc, vkofs);

  /* Copy out old index list */
  CREATE(tmplist,int32_t,nk->no_values);
  memcpy(tmplist, vlistkey, nk->no_values * sizeof(int32_t));

  free_block(hdesc,vlistofs-4);  /* Get rid of old list */

  nk->no_values--;

  if (nk->no_values) {
    newlistofs = alloc_block(hdesc, vlistofs, nk->no_values * sizeof(int32_t));
    if (!newlistofs) {
    }
    /* Now copy over, omitting deleted entry */
    newlistkey = (int32_t *)(hdesc->buffer + newlistofs + 4);
    for (n = 0, o = 0; o < nk->no_values+1; o++, n++) {
      if (o == slot) o++;
      newlistkey[n] = tmplist[o];
    }
    nk->ofs_vallist = newlistofs - 0x1000;
  } else {
    nk->ofs_vallist = -1;
  }
  return(0);
}



#define AKDEBUG 1
struct nk_key *add_key(struct hive *hdesc, int nkofs, char *name)
{

  int slot, newlfofs = 0, oldlfofs = 0, newliofs = 0;
  int oldliofs = 0;
  int o, n, i, onkofs, newnkofs, cmp;
  int rimax, rislot, riofs, namlen;
  struct ri_key *ri = NULL;
  struct lf_key *newlf = NULL, *oldlf;
  struct li_key *newli = NULL, *oldli;
  struct nk_key *key, *newnk, *onk;
  int32_t hash;

  key = (struct nk_key *)(hdesc->buffer + nkofs);

  if (key->id != 0x6b6e) {
    return(NULL);
  }

  namlen = strlen(name);

  slot = -1;
  if (key->no_subkeys) {   /* It already has subkeys */
    
    oldlfofs = key->ofs_lf;
    oldliofs = key->ofs_lf;
   
    oldlf = (struct lf_key *)(hdesc->buffer + oldlfofs + 0x1004);
    if (oldlf->id != 0x666c && oldlf->id != 0x686c && oldlf->id != 0x696c && oldlf->id != 0x6972)  {
      return(NULL);
    }

    rimax = 0; ri = NULL; riofs = 0; rislot = -1;
    if (oldlf->id == 0x6972) {  /* Indirect index 'ri', init loop */
      riofs = key->ofs_lf;
      ri = (struct ri_key *)(hdesc->buffer + riofs + 0x1004);
      rimax = ri->no_lis-1;
      oldliofs = ri->hash[rislot+1].ofs_li;
      oldlfofs = ri->hash[rislot+1].ofs_li;

    }

    do {   /* 'ri' loop, at least run once if no 'ri' deep index */

      if (ri) { /* Do next 'ri' slot */
	rislot++;
	oldliofs = ri->hash[rislot].ofs_li;
	oldlfofs = ri->hash[rislot].ofs_li;
	oldli = (struct li_key *)(hdesc->buffer + oldliofs + 0x1004);
	oldlf = (struct lf_key *)(hdesc->buffer + oldlfofs + 0x1004);
      }

      oldli = (struct li_key *)(hdesc->buffer + oldliofs + 0x1004);
      oldlf = (struct lf_key *)(hdesc->buffer + oldlfofs + 0x1004);

      slot = -1;

      if (oldli->id == 0x696c) {  /* li */

	FREE(newli);
	ALLOC(newli, 8 + 4*oldli->no_keys + 4, 1);
	newli->no_keys = oldli->no_keys;
	newli->id = oldli->id;
	
	/* Now copy old, checking where to insert (alphabetically) */
	for (o = 0, n = 0; o < oldli->no_keys; o++,n++) {
	  onkofs = oldli->hash[o].ofs_nk;
	  onk = (struct nk_key *)(onkofs + hdesc->buffer + 0x1004);
	  if (slot == -1) {

	    cmp = strncasecmp(name, onk->keyname, (namlen > onk->len_name) ? namlen : onk->len_name);
	    if (!cmp) {
	      FREE(newli);
	      return(NULL);
	    }
	    if ( cmp < 0) {
	      slot = o;
	      rimax = rislot; /* Cause end of 'ri' search, too */
	      n++;
	    }
	  }
	  newli->hash[n].ofs_nk = oldli->hash[o].ofs_nk;
	}
	if (slot == -1) slot = oldli->no_keys;
	
      } else { /* lf or lh */

	oldlf = (struct lf_key *)(hdesc->buffer + oldlfofs + 0x1004);
	
	FREE(newlf);
	ALLOC(newlf, 8 + 8*oldlf->no_keys + 8, 1);
	newlf->no_keys = oldlf->no_keys;
	newlf->id = oldlf->id;
	/* Now copy old, checking where to insert (alphabetically) */
	for (o = 0, n = 0; o < oldlf->no_keys; o++,n++) {
	  onkofs = oldlf->hash[o].ofs_nk;
	  onk = (struct nk_key *)(onkofs + hdesc->buffer + 0x1004);
	  if (slot == -1) {
	    cmp = strncasecmp(name, onk->keyname, (namlen > onk->len_name) ? namlen : onk->len_name);
	    if (!cmp) {
	      FREE(newlf);
	      return(NULL);
	    }
	    if ( cmp < 0 ) {
	      slot = o;
	      rimax = rislot;  /* Cause end of 'ri' search, too */
	      n++;
	    }
	  }
	  newlf->hash[n].ofs_nk = oldlf->hash[o].ofs_nk;
	  newlf->hash[n].name[0] = oldlf->hash[o].name[0];
	  newlf->hash[n].name[1] = oldlf->hash[o].name[1];
	  newlf->hash[n].name[2] = oldlf->hash[o].name[2];
	  newlf->hash[n].name[3] = oldlf->hash[o].name[3];
	}
	if (slot == -1) slot = oldlf->no_keys;
      } /* li else check */


    } while ( (rislot < rimax) && (rimax > 0));  /* 'ri' wrapper loop */

  } else { /* Parent was empty, make new index block */
    ALLOC(newlf, 8 + 8, 1);
    newlf->no_keys = 1;
    /* Use ID (lf, lh or li) we fetched from root node, so we use same as rest of hive */
    newlf->id = hdesc->nkindextype;
    slot = 0;
  } /* if has keys before */


  /* Make and fill in new nk */
  newnkofs = alloc_block(hdesc, nkofs, sizeof(struct nk_key) + strlen(name));
  if (!newnkofs) {
    FREE(newlf);
    FREE(newli);
    return(NULL);
  }
  newnk = (struct nk_key *)(hdesc->buffer + newnkofs + 4);
  
  newnk->id            = 0x6b6e;
  newnk->type          = KEY_NORMAL;
  newnk->ofs_parent    = nkofs - 0x1004;
  newnk->no_subkeys    = 0;
  newnk->ofs_lf        = 0;
  newnk->no_values     = 0;
  newnk->ofs_vallist   = -1;
  newnk->ofs_sk        = key->ofs_sk; /* Get parents for now. 0 or -1 here crashes XP */
  newnk->ofs_classnam  = -1;
  newnk->len_name      = strlen(name);
  newnk->len_classnam  = 0;
  strcpy(newnk->keyname, name);
  
  if (newli) {  /* Handle li */
    /* And put its offset into parents index list */
    newli->hash[slot].ofs_nk = newnkofs - 0x1000;
    newli->no_keys++;
    
    /* Allocate space for our new li list and copy it into reg */
    newliofs = alloc_block(hdesc, nkofs, 8 + 4*newli->no_keys);
    if (!newliofs) {
      FREE(newli);
      free_block(hdesc,newnkofs);
      return(NULL);
    }
    /*    memcpy(hdesc->buffer + newliofs + 4, newli, 8 + 4*newli->no_keys); */
    fill_block(hdesc, newliofs, newli, 8 + 4*newli->no_keys);


  } else {  /* lh or lf */
    /* And put its offset into parents index list */
    newlf->hash[slot].ofs_nk = newnkofs - 0x1000;
    newlf->no_keys++;
    if (newlf->id == 0x666c) {        /* lf hash */
      newlf->hash[slot].name[0] = 0;
      newlf->hash[slot].name[1] = 0;
      newlf->hash[slot].name[2] = 0;
      newlf->hash[slot].name[3] = 0;
      strncpy(newlf->hash[slot].name, name, 4);
    } else if (newlf->id == 0x686c) {  /* lh. XP uses this. hashes whole name */
      for (i = 0,hash = 0; i < strlen(name); i++) {
	hash *= 37;
	hash += toupper(name[i]);
      }
      newlf->lh_hash[slot].hash = hash;
    }
    
    /* Allocate space for our new lf list and copy it into reg */
    newlfofs = alloc_block(hdesc, nkofs, 8 + 8*newlf->no_keys);
    if (!newlfofs) {
      FREE(newlf);
      free_block(hdesc,newnkofs);
      return(NULL);
    }
    /*    memcpy(hdesc->buffer + newlfofs + 4, newlf, 8 + 8*newlf->no_keys); */
    fill_block(hdesc, newlfofs, newlf, 8 + 8*newlf->no_keys);
    
  } /* li else */


  /* Update parent, and free old lf list */
  key->no_subkeys++;
  if (ri) {  /* ri index */
    ri->hash[rislot].ofs_li = (newlf ? newlfofs : newliofs) - 0x1000;
  } else { /* Parent key */
    key->ofs_lf = (newlf ? newlfofs : newliofs) - 0x1000;
  }

  if (newlf && oldlfofs) free_block(hdesc,oldlfofs + 0x1000);
  if (newli && oldliofs) free_block(hdesc,oldliofs + 0x1000);

  FREE(newlf);
  FREE(newli);
  return(newnk);


}


#undef DKDEBUG

int del_key(struct hive *hdesc, int nkofs, char *name)
{

  int slot = 0, newlfofs = 0, oldlfofs = 0, o, n, onkofs,  delnkofs;
  int oldliofs = 0, no_keys = 0, newriofs = 0;
  int namlen;
  int rimax, riofs, rislot;
  struct ri_key *ri, *newri = NULL;
  struct lf_key *newlf = NULL, *oldlf = NULL;
  struct li_key *newli = NULL, *oldli = NULL;
  struct nk_key *key, *onk, *delnk;
  char fullpath[501];

  key = (struct nk_key *)(hdesc->buffer + nkofs);

  namlen = strlen(name);

  if (key->id != 0x6b6e) {
    return(1);
  }

  slot = -1;
  if (!key->no_subkeys) {
    return(1);
  }

  oldlfofs = key->ofs_lf;
  oldliofs = key->ofs_lf;
  
  oldlf = (struct lf_key *)(hdesc->buffer + oldlfofs + 0x1004);
  if (oldlf->id != 0x666c && oldlf->id != 0x686c && oldlf->id != 0x696c && oldlf->id != 0x6972)  {
    return(1);
  }

  rimax = 0; ri = NULL; riofs = 0;
  rislot = 0;

  if (oldlf->id == 0x6972) {  /* Indirect index 'ri', init loop */
    riofs = key->ofs_lf;
    ri = (struct ri_key *)(hdesc->buffer + riofs + 0x1004);
    rimax = ri->no_lis-1;

    rislot = -1; /* Starts at slot 0 below */
    
  }
  
  do {   /* 'ri' loop, at least run once if no 'ri' deep index */
    
    if (ri) { /* Do next 'ri' slot */
      rislot++;
      oldliofs = ri->hash[rislot].ofs_li;
      oldlfofs = ri->hash[rislot].ofs_li;
    }
    
    oldli = (struct li_key *)(hdesc->buffer + oldliofs + 0x1004);
    oldlf = (struct lf_key *)(hdesc->buffer + oldlfofs + 0x1004);

    slot = -1;
    
    if (oldlf->id == 0x696c) {   /* 'li' handler */
      
      FREE(newli);
      ALLOC(newli, 8 + 4*oldli->no_keys - 4, 1);
      newli->no_keys = oldli->no_keys - 1; no_keys = newli->no_keys;
      newli->id = oldli->id;
      
      /* Now copy old, checking where to delete */
      for (o = 0, n = 0; o < oldli->no_keys; o++,n++) {
	onkofs = oldli->hash[o].ofs_nk;
	onk = (struct nk_key *)(onkofs + hdesc->buffer + 0x1004);
	if (slot == -1 && onk->len_name == namlen && !strncmp(name, onk->keyname, (onk->len_name > namlen) ? onk->len_name : namlen)) {
	  slot = o;
	  delnkofs = onkofs; delnk = onk;
	  rimax = rislot;
	  o++;
	}
	newli->hash[n].ofs_nk = oldli->hash[o].ofs_nk;
      }
      
      
    } else { /* 'lf' or 'lh' are similar */
      
      FREE(newlf);
      ALLOC(newlf, 8 + 8*oldlf->no_keys - 8, 1);
      newlf->no_keys = oldlf->no_keys - 1; no_keys = newlf->no_keys;
      newlf->id = oldlf->id;
      
      /* Now copy old, checking where to delete */
      for (o = 0, n = 0; o < oldlf->no_keys; o++,n++) {
	onkofs = oldlf->hash[o].ofs_nk;
	onk = (struct nk_key *)(onkofs + hdesc->buffer + 0x1004);
	if (slot == -1 && (onk->len_name == namlen) && !strncmp(name, onk->keyname, onk->len_name)) {
	  slot = o;
	  delnkofs = onkofs; delnk = onk;
	  rimax = rislot;
	  o++;
	}
	newlf->hash[n].ofs_nk = oldlf->hash[o].ofs_nk;
	newlf->hash[n].name[0] = oldlf->hash[o].name[0];
	newlf->hash[n].name[1] = oldlf->hash[o].name[1];
	newlf->hash[n].name[2] = oldlf->hash[o].name[2];
	newlf->hash[n].name[3] = oldlf->hash[o].name[3];
      }
    } /* else lh or lf */

  } while (rislot < rimax);  /* ri traverse loop */

  if (slot == -1) {
    FREE(newlf);
    FREE(newli);
    return(1);
  }

  if (delnk->no_values || delnk->no_subkeys) {
    FREE(newlf);
    FREE(newli);
    return(1);
  }

  /* Allocate space for our new lf list and copy it into reg */
  if ( no_keys && (newlf || newli) ) {
    newlfofs = alloc_block(hdesc, nkofs, 8 + (newlf ? 8 : 4) * no_keys);
    if (!newlfofs) {
      FREE(newlf);
      return(1);
    }

    /*    memcpy(hdesc->buffer + newlfofs + 4,
	   ((void *)newlf ? (void *)newlf : (void *)newli), 8 + (newlf ? 8 : 4) * no_keys);
    */
    fill_block(hdesc, newlfofs,
	   ((void *)newlf ? (void *)newlf : (void *)newli), 8 + (newlf ? 8 : 4) * no_keys);


  } else {  /* Last deleted, will throw away index */
    newlfofs = 0xfff;  /* We subtract 0x1000 later */
  }

  if (newlfofs < 0xfff) {
  }

  /* Check for CLASS data, if so, deallocate it too */
  if (delnk->len_classnam) {
    free_block(hdesc, delnk->ofs_classnam + 0x1000);
  }
  /* Now it's safe to zap the nk */
  free_block(hdesc, delnkofs + 0x1000);
  /* And the old index list */
  free_block(hdesc, (oldlfofs ? oldlfofs : oldliofs) + 0x1000);

  /* Update parent */
  key->no_subkeys--;

  if (ri) {
    if (newlfofs == 0xfff) {

      *fullpath = 0;
      get_abs_path(hdesc, nkofs, fullpath, 480);

      if (ri->no_lis > 1) {  /* We have subindiceblocks left? */
	/* Delete from array */
	ALLOC(newri, 8 + 4*ri->no_lis - 4, 1);
	newri->no_lis = ri->no_lis - 1;
	newri->id = ri->id;
	for (o = 0, n = 0; o < ri->no_lis; o++,n++) {
	  if (n == rislot) o++;
	  newri->hash[n].ofs_li = ri->hash[o].ofs_li;
	}
	newriofs = alloc_block(hdesc, nkofs, 8 + newri->no_lis*4 );
	if (!newriofs) {
	  FREE(newlf);
	  FREE(newri);
	  return(1);
	}
	fill_block(hdesc, newriofs, newri, 8 + newri->no_lis * 4);
	free_block(hdesc, riofs + 0x1000);
	key->ofs_lf = newriofs - 0x1000;
	FREE(newri);
      } else {
	free_block(hdesc, riofs + 0x1000);
	key->ofs_lf = -1;
      }
    } else {
      ri->hash[rislot].ofs_li = newlfofs - 0x1000; 
    }
  } else {
    key->ofs_lf = newlfofs - 0x1000;
  }

  FREE(newlf);
  return(0);

}

void rdel_keys(struct hive *hdesc, char *path, int vofs)
{
  struct nk_key *key;
  int nkofs;
  struct ex_data ex;
  int count = 0, countri = 0;
  

  if (!path || !*path) return;

  nkofs = trav_path(hdesc, vofs, path, TPF_NK_EXACT);

  if(!nkofs) {
    return;
  }
  nkofs += 4;

  key = (struct nk_key *)(hdesc->buffer + nkofs);

  /*
  VERBF(hdesc,"rdel of node at offset 0x%0x\n",nkofs);
  */

  if (key->id != 0x6b6e) {

    
  }
  
  if (key->no_subkeys) {
    while ((ex_next_n(hdesc, nkofs, &count, &countri, &ex) > 0)) {
      rdel_keys(hdesc, ex.name, nkofs);
      count = 0;
      countri = 0;
      FREE(ex.name);
    }
  }

  del_allvalues(hdesc, nkofs);
  del_key(hdesc, key->ofs_parent+0x1004, path);

}
  

struct keyval *get_class(struct hive *hdesc,
			    int curnk, char *path)
{
  int clen = 0, dofs = 0, nkofs;
  struct nk_key *key;
  struct keyval *data;
  void *classdata;

  if (!path && !curnk) return(NULL);

  nkofs = trav_path(hdesc, curnk, path, 0);

  if(!nkofs) {
    return(NULL);
  }
  nkofs += 4;
  key = (struct nk_key *)(hdesc->buffer + nkofs);

  clen = key->len_classnam;
  if (!clen) {
    return(NULL);
  }

  dofs = key->ofs_classnam;
  classdata = (void *)(hdesc->buffer + dofs + 0x1004);
  

  ALLOC(data, sizeof(struct keyval) + clen,1);
  data->len = clen;
  memcpy(&data->data, classdata, clen);
  return(data);
}


/* Write to registry value.
 * If same size as existing, copy back in place to avoid changing too much
 * otherwise allocate new dataspace, then free the old
 * Thus enough space to hold both new and old data is needed
 * Pass inn buffer with data len as first DWORD (as routines above)
 * returns: 0 - error, len - OK (len of data)
 */

int put_buf2val(struct hive *hdesc, struct keyval *kv,
		int vofs, char *path, int type, int exact )
{
  int l;
  void *keydataptr;

  if (!kv) return(0);
  l = get_val_len(hdesc, vofs, path, exact);
  if (l == -1) return(0);  /* error */
  if (kv->len != l) {  /* Realloc data block if not same size as existing */
    if (!alloc_val_data(hdesc, vofs, path, kv->len, exact)) {
      return(0);
    }
  }

  keydataptr = get_val_data(hdesc, vofs, path, type, exact);
  if (!keydataptr) return(0); /* error */

  memcpy(keydataptr, &kv->data, kv->len);

  hdesc->state |= HMODE_DIRTY;

  return(kv->len);
}

/* And, yer basic DWORD write */

int put_dword(struct hive *hdesc, int vofs, char *path, int exact, int dword)
{
  struct keyval *kr;
  int r;

  ALLOC(kr,1,sizeof(int)+sizeof(int));
  
  kr->len = sizeof(int);
  kr->data = dword;

  r = put_buf2val(hdesc, kr, vofs, path, REG_DWORD, exact);

  FREE(kr);

  return(r);
}

char * convert_string(void *string, int len)
{
    int i, k;
    int reallen = len / 2;
    char *cstring = (char *)malloc(reallen);

    for(i = 0, k = 0; i < len; i += 2, k++)
    {
        cstring[k] = ((char *)string)[i];
    }
    cstring[reallen - 1] = '\0';

    return cstring;
}

void export_subkey(struct hive *hdesc, int nkofs, char *name, char *prefix, FILE *file)
{
    int newofs;
    int count = 0;
    int countri = 0;
    int len, byte;
    char keyname[128];
    char path[1024];
    char *value;
    struct nk_key *key;
    struct ex_data ex;
    struct vex_data vex;


    // switch to key
    newofs = trav_path(hdesc, nkofs, name, TPF_NK_EXACT);
    if(!newofs)
    {
        return;
    }
    nkofs = newofs + 4;

    // get the key
    key = (struct nk_key *)(hdesc->buffer + nkofs);
    strncpy(keyname, key->keyname, key->len_name);
    keyname[key->len_name] = '\0';

    *path = 0;
    get_abs_path(hdesc, nkofs, path, 1024);

    // export the key
    fprintf(file, "\r\n");
    fprintf(file, "[%s\%s]\r\n", prefix, path);
    // export values
    if(key->no_values)
    {
        while ((ex_next_v(hdesc, nkofs, &count, &vex) > 0))
        {
            if(vex.type == REG_DWORD)
            {
                fprintf(file, "\"%s\"=dword:%08x\r\n", vex.name, vex.val);
            }
            else if(vex.type == REG_SZ)
            {
	        value = (char *)get_val_data(hdesc, nkofs, vex.name, vex.type, TPF_VK_EXACT);
	        len = get_val_len(hdesc, nkofs, vex.name, TPF_VK_EXACT);

                fprintf(file, "\"%s\"=\"%s\"", vex.name, convert_string(value, len));
                fprintf(file, "\r\n");
            }
	    else
            {
	      value = (char *)get_val_data(hdesc, nkofs, vex.name, vex.type, TPF_VK_EXACT);
	      len = get_val_len(hdesc, nkofs, vex.name, TPF_VK_EXACT);

	      if (vex.type == REG_BINARY) {
		fprintf(file, "\"%s\"=hex:", vex.name);
	      } else {
		fprintf(file, "\"%s\"=hex(%x):", vex.name, vex.type);
	      }
	      byte = 0;
	      while (byte < len) { /* go byte by byte.. probably slow.. */
		fprintf(file, "%02x,", (unsigned char)value[byte]);
		byte++;
		if (!(byte % 20)) fprintf(file, "\\\r\n  ");
	      }
	      fprintf(file, "%02x\r\n", (unsigned char)value[byte]);
            }

            FREE(vex.name);
        }
    }

    // export subkeys
    if (key->no_subkeys)
    {
        count = 0;
        countri = 0;
        while ((ex_next_n(hdesc, nkofs, &count, &countri, &ex) > 0))
        {
            export_subkey(hdesc, nkofs, ex.name, prefix, file);
            FREE(ex.name);
        }
    }
}

void export_key(struct hive *hdesc, int nkofs, char *name, char *filename, char *prefix)
{
    FILE *file;

    // open file
    file = fopen(filename, "w");
    if(!file)
    {
        return;
    }
        fprintf(file, "Windows Registry Editor Version 5.00\r\n\r\n");
    export_subkey(hdesc, nkofs, name, prefix, file);

    fclose(file);
}


void closeHive(struct hive *hdesc)
{
  if (hdesc->state & HMODE_OPEN) {
    close(hdesc->filedesc);
  }
  FREE(hdesc->filename);
  FREE(hdesc->buffer);
  FREE(hdesc);

}

/* Write the hive back to disk (only if dirty & not readonly */
int writeHive(struct hive *hdesc)
{
  int len;

  if (hdesc->state & HMODE_RO) return(0);
  if ( !(hdesc->state & HMODE_DIRTY)) return(0);

  if ( !(hdesc->state & HMODE_OPEN)) { /* File has been closed */
    if (!(hdesc->filedesc = open(hdesc->filename,O_RDWR))) {
      return(1);
    }
    hdesc->state |= HMODE_OPEN;
  }  
  /* Seek back to begginning of file (in case it's already open) */
  lseek(hdesc->filedesc, 0, SEEK_SET);

  len = write(hdesc->filedesc, hdesc->buffer, hdesc->size);
  if (len != hdesc->size) {
    return(1);
  }

  hdesc->state &= (~HMODE_DIRTY);
  return(0);
}

struct hive *openHive(char *filename, int mode)
{

  struct hive *hdesc;
  int fmode,r,vofs;
  struct stat sbuf;
  uint32_t pofs;
  /* off_t l; */
  char *c;
  struct hbin_page *p;
  struct regf_header *hdr;
  struct nk_key *nk;
  struct ri_key *rikey;
  int verbose = (mode & HMODE_VERBOSE);
  int trace   = (mode & HMODE_TRACE);

  CREATE(hdesc,struct hive,1);

  hdesc->filename = str_dup(filename);
  hdesc->state = 0;
  hdesc->size = 0;
  hdesc->buffer = NULL;

  if ( (mode & HMODE_RO) ) {
    fmode = O_RDONLY;
  } else {
    fmode = O_RDWR;
  }
  hdesc->filedesc = open(hdesc->filename,fmode);
  if (hdesc->filedesc < 0) {
    fmode = O_RDONLY;
    mode |= HMODE_RO;
    hdesc->filedesc = open(hdesc->filename,fmode);
    if (hdesc->filedesc < 0) {
      closeHive(hdesc);
      return(NULL);
    }
  }


  if ( fstat(hdesc->filedesc,&sbuf) ) {
    exit(1);
  }

  hdesc->size = sbuf.st_size;
  hdesc->state = mode | HMODE_OPEN;
  ALLOC(hdesc->buffer,1,hdesc->size);
  FILE* fp = fopen(filename, "rb");
  r = fread(hdesc->buffer, 1, hdesc->size, fp);
  fclose(fp);
  //r = read(hdesc->filedesc,hdesc->buffer,hdesc->size);
  if (r < hdesc->size) {
    closeHive(hdesc);
    return(NULL);
  }

  /* Now run through file, tallying all pages */
  /* NOTE/KLUDGE: Assume first page starts at offset 0x1000 */

   pofs = 0x1000;

   hdr = (struct regf_header *)hdesc->buffer;
   if (hdr->id != 0x66676572) {
     return(hdesc);
   }

   hdesc->rootofs = hdr->ofs_rootkey + 0x1000;
   
   nk = (struct nk_key *)(hdesc->buffer + hdesc->rootofs + 4);
   if (nk->id == 0x6b6e) {
     rikey = (struct ri_key *)(hdesc->buffer + nk->ofs_lf + 0x1004);
     hdesc->nkindextype = rikey->id;
     if (hdesc->nkindextype == 0x6972) {
       rikey = (struct ri_key *)(hdesc->buffer + rikey->hash[0].ofs_li + 0x1004);
       hdesc->nkindextype = rikey->id;
     }
     if (hdesc->nkindextype != 0x666c &&
	 hdesc->nkindextype != 0x686c &&
	 hdesc->nkindextype != 0x696c) {
       hdesc->nkindextype = 0x666c;
     }
   } else {
   }



   while (pofs < hdesc->size) {
     p = (struct hbin_page *)(hdesc->buffer + pofs);
     if (p->id != 0x6E696268) {
       break;
     }
     hdesc->pages++;
     if (p->ofs_next == 0) {
       return(hdesc);
     }


     vofs = pofs + 0x20; /* Skip page header */
#if 1
     while (vofs-pofs < p->ofs_next && vofs < hdesc->size) {
       vofs += parse_block(hdesc,vofs,trace);

     }
#endif
     pofs += p->ofs_next;
   }
  

   /* So, let's guess what kind of hive this is, based on keys in its root */

   hdesc->type = HTYPE_UNKNOWN;
   if (trav_path(hdesc, 0, "\\SAM", 0)) hdesc->type = HTYPE_SAM;
   else if (trav_path(hdesc, 0, "\\ControlSet", 0)) hdesc->type = HTYPE_SYSTEM;
   else if (trav_path(hdesc, 0, "\\Policy", 0)) hdesc->type = HTYPE_SECURITY;
   else if (trav_path(hdesc, 0, "\\Microsoft", 0)) hdesc->type = HTYPE_SOFTWARE;   

  return(hdesc);

}

