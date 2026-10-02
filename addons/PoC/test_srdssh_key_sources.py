"""Compile and exercise the actual Dropbear key-source selection code."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE=Path(__file__).parent/"srdsh-work/srdsh/vendor/dropbear/src/svr-authpubkey.c"

HARNESS=r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#define DROPBEAR_FAILURE -1
#define DROPBEAR_SUCCESS 0
#define DROPBEAR_SVR_MULTIUSER 0
#define MAX_AUTHKEYS_LINE 4200
#define TRACE(x)
#define m_malloc(n) malloc(n)
#define m_free(p) do { free(p); (p)=NULL; } while (0)
typedef struct {char text[MAX_AUTHKEYS_LINE];} buffer;
struct { struct {uid_t pw_uid;gid_t pw_gid;char *pw_dir;char *pubkey_info;} authstate;} ses;
static int permissions_allowed;
static int permissions_checked;
static buffer *buf_new(unsigned int n) {(void)n;return calloc(1,sizeof(buffer));}
static void buf_free(buffer *b) {free(b);}
static int buf_getline(buffer *b,FILE *f) {
 if(!fgets(b->text,sizeof(b->text),f)) return DROPBEAR_FAILURE;
 b->text[strcspn(b->text,"\r\n")]=0;return DROPBEAR_SUCCESS;
}
static int checkpubkey_line(buffer *line,int number,const char *filename,
 const char *algorithm,unsigned int algolen,const unsigned char *key,unsigned int keylen,char **info) {
 (void)number;(void)filename;(void)algorithm;(void)algolen;(void)keylen;(void)info;
 return strcmp(line->text,(const char *)key)==0 ? DROPBEAR_SUCCESS : DROPBEAR_FAILURE;
}
static int checkpubkeyperms(void) {
 struct stat state;char file[4096];permissions_checked++;
 snprintf(file,sizeof(file),"%s/.ssh/authorized_keys",ses.authstate.pw_dir);
 return permissions_allowed && stat(file,&state)==0 && !(state.st_mode & 077)
  ? DROPBEAR_SUCCESS : DROPBEAR_FAILURE;
}
'''

MAIN=r'''
int main(int argc,char **argv) {
 if(argc!=6) return 2;
 ses.authstate.pw_uid=atoi(argv[1]);ses.authstate.pw_dir=argv[2];permissions_allowed=atoi(argv[4]);
 if(strcmp(argv[3],"absent")!=0) setenv("CRYPTEX_MOUNT_PATH",argv[3],1);
 else unsetenv("CRYPTEX_MOUNT_PATH");
 int result=checkpubkey("test",4,(const unsigned char *)argv[5],strlen(argv[5]));
 printf("%d %d\n",result,permissions_checked);return 0;
}
'''


class KeySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory()
        root=Path(cls.temporary.name)
        source=SOURCE.read_text()
        start=source.index("static int checkpubkey_file(FILE")
        end=source.index("/* Returns DROPBEAR_SUCCESS if file permissions",start)
        harness=root/"key_sources.c"
        harness.write_text(HARNESS+source[start:end]+MAIN)
        cls.binary=root/"key_sources"
        subprocess.run([shutil.which("clang"),str(harness),"-o",str(cls.binary)],check=True,capture_output=True)

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def check(self,key,uid=0,normal=True,mode=0o600,permissions=True):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);home=root/"home";mount=root/"cryptex"
            (home/".ssh").mkdir(parents=True,mode=0o700)
            (mount/"etc").mkdir(parents=True)
            (mount/"etc/srdsh_authorized_key").write_text("SEALED\n")
            if normal:
                path=home/".ssh/authorized_keys";path.write_text("ENROLLED\n");path.chmod(mode)
            result=subprocess.run([str(self.binary),str(uid),str(home),str(mount),str(int(permissions)),key],
                                  check=True,capture_output=True,text=True)
            return tuple(map(int,result.stdout.split()))

    def test_original_sealed_root_key_still_works_without_home_keys(self):
        self.assertEqual(self.check("SEALED",normal=False,permissions=False),(0,0))

    def test_additional_root_key_is_checked_after_sealed_key_mismatch(self):
        self.assertEqual(self.check("ENROLLED"),(0,1))

    def test_insecure_mutable_key_file_is_rejected(self):
        self.assertEqual(self.check("ENROLLED",mode=0o666),(-1,1))

    def test_failed_owner_permission_check_is_not_bypassed(self):
        self.assertEqual(self.check("ENROLLED",permissions=False),(-1,1))

    def test_sealed_root_key_cannot_authorize_nonroot_user(self):
        self.assertEqual(self.check("SEALED",uid=501),(-1,1))

    def test_nonroot_user_can_use_secure_home_key(self):
        self.assertEqual(self.check("ENROLLED",uid=501),(0,1))


if __name__=="__main__": unittest.main()
