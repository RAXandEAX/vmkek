#include <stdio.h>
#include <z3.h>

static Z3_lbool check(Z3_context ctx, const char *query) {
    Z3_solver solver = Z3_mk_solver(ctx);
    Z3_solver_inc_ref(ctx, solver);
    Z3_solver_from_string(ctx, solver, query);
    Z3_lbool status = Z3_solver_check(ctx, solver);
    Z3_solver_dec_ref(ctx, solver);
    return status;
}

int main(void) {
    const char equivalent[] =
        "(declare-const a (_ BitVec 64))(declare-const b (_ BitVec 64))"
        "(define-fun left () (_ BitVec 64) "
        "(bvxor (bvadd (bvmul a (_ bv7 64)) (_ bv3 64)) b))"
        "(define-fun right () (_ BitVec 64) "
        "(bvxor b (bvadd (_ bv3 64) (bvmul (_ bv7 64) a))))"
        "(assert (distinct left right))";
    const char changed[] =
        "(declare-const a (_ BitVec 64))(declare-const b (_ BitVec 64))"
        "(assert (distinct (bvxor (bvadd (bvmul a (_ bv7 64)) (_ bv3 64)) b)"
        "(bvxor (bvadd (bvmul a (_ bv7 64)) (_ bv4 64)) b)))";
    Z3_config config = Z3_mk_config();
    Z3_context ctx = Z3_mk_context(config);
    Z3_del_config(config);
    Z3_lbool good = check(ctx, equivalent);
    Z3_lbool bad = check(ctx, changed);
    Z3_del_context(ctx);
    printf("Z3 %s, equivalence %d, changed %d\n", Z3_get_full_version(), good, bad);
    return good == Z3_L_FALSE && bad == Z3_L_TRUE ? 0 : 2;
}
