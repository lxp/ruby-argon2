#include <ruby.h>

#include "argon_wrap.c"

void my_memcpy(char *dest, char *src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char tmp = src[i];
        dest[i] = tmp;
    }
}

char *truffle_to_cstr(VALUE src) {
    size_t len = RSTRING_LEN(src);
    char *cstr = malloc(len + 1);
    my_memcpy(cstr, RSTRING_PTR(src), len);
    cstr[len] = '\0';
    return cstr;
}

static VALUE cext_argon2i_hash_raw(VALUE self, VALUE t_cost, VALUE m_cost, VALUE parallelism, VALUE pwd, VALUE salt) {
    char hash[OUT_LEN];
    char *pwdcstr = truffle_to_cstr(pwd);
    uint8_t *saltcstr = (uint8_t*) truffle_to_cstr(salt);

    int ret = argon2i_hash_raw(NUM2UINT(t_cost), NUM2UINT(m_cost), NUM2UINT(parallelism), pwdcstr, RSTRING_LEN(pwd), saltcstr, RSTRING_LEN(salt), hash, OUT_LEN);

    free(pwdcstr);
    free(saltcstr);

    if (ret != 0) {
        return INT2NUM(ret);
    }
    return rb_str_new(hash, OUT_LEN);
}

static VALUE cext_argon2_wrap(VALUE self, VALUE pwd, VALUE salt, VALUE t_cost, VALUE m_cost, VALUE lanes, VALUE secret) {
    char out[ENCODE_LEN];
    char *pwdcstr;
    size_t pwdlen;
    if (NIL_P(pwd)) {
        pwdcstr = NULL;
        pwdlen = 0;
    } else {
        pwdcstr = truffle_to_cstr(pwd);
        pwdlen = RSTRING_LEN(pwd);
    }
    uint8_t *saltcstr = (uint8_t*) truffle_to_cstr(salt);
    uint8_t *secretcstr;
    size_t secretlen;
    if (NIL_P(secret)) {
        secretcstr = NULL;
        secretlen = 0;
    } else {
        secretcstr = (uint8_t*) truffle_to_cstr(secret);
        secretlen = RSTRING_LEN(secret);
    }

    unsigned int ret = argon2_wrap(out, pwdcstr, pwdlen, saltcstr, NUM2UINT(t_cost), NUM2UINT(m_cost), NUM2UINT(lanes), secretcstr, secretlen);

    free(pwdcstr);
    free(saltcstr);
    free(secretcstr);

    if (ret != 0) {
        return UINT2NUM(ret);
    }
    return rb_str_new_cstr(out);
}

static VALUE cext_wrap_argon2_verify(VALUE self, VALUE encoded, VALUE pwd, VALUE secret) {
    char *encodedcstr = truffle_to_cstr(encoded);
    char *pwdcstr;
    size_t pwdlen;
    if (NIL_P(pwd)) {
        pwdcstr = NULL;
        pwdlen = 0;
    } else {
        pwdcstr = truffle_to_cstr(pwd);
        pwdlen = RSTRING_LEN(pwd);
    }
    uint8_t *secretcstr;
    size_t secretlen;
    if (NIL_P(secret)) {
        secretcstr = NULL;
        secretlen = 0;
    } else {
        secretcstr = (uint8_t*) truffle_to_cstr(secret);
        secretlen = RSTRING_LEN(secret);
    }

    int ret = wrap_argon2_verify(encodedcstr, pwdcstr, pwdlen, secretcstr, secretlen);

    free(encodedcstr);
    free(pwdcstr);
    free(secretcstr);

    return INT2NUM(ret);
}

void Init_argon2(void) {
    VALUE rb_mArgon2 = rb_define_module("Argon2");
    VALUE rb_mCExt = rb_define_module_under(rb_mArgon2, "CExt");
    rb_define_module_function(rb_mCExt, "argon2i_hash_raw", cext_argon2i_hash_raw, 5);
    rb_define_module_function(rb_mCExt, "argon2_wrap", cext_argon2_wrap, 6);
    rb_define_module_function(rb_mCExt, "wrap_argon2_verify", cext_wrap_argon2_verify, 3);
}

