#include "bochs.h"
#include "gui/siminterface.h"
#include <map>
#include <string>


static std::map<std::string, bx_param_enum_c*> enums;
static std::map<std::string, bx_param_string_c*> strings;
static std::map<std::string, bx_param_bool_c*> bools;
static std::map<std::string, bx_param_num_c*> nums;
static void init_params(void);

class bx_real_sim_c : public bx_simulator_interface_c {
public:
    bx_real_sim_c();
    virtual bx_param_enum_c *get_param_enum(const char *pname, bx_param_c *base=NULL);
    virtual bx_param_num_c *get_param_num(const char *pname, bx_param_c *base=NULL);
    virtual bx_param_bool_c *get_param_bool(const char *pname, bx_param_c *base=NULL);
    virtual bx_param_string_c *get_param_string(const char *pname, bx_param_c *base=NULL);
};

bx_real_sim_c::bx_real_sim_c() {
}

bx_param_enum_c *bx_real_sim_c::get_param_enum(const char *pname, bx_param_c *base)
{
    printf("get param %s\n", pname);
    return enums[pname];
}

bx_param_num_c *bx_real_sim_c::get_param_num(const char *pname, bx_param_c *base)
{
    printf("get param %s\n", pname);
    return nums[pname];
}

bx_param_bool_c *bx_real_sim_c::get_param_bool(const char *pname, bx_param_c *base)
{
    printf("get param %s\n", pname);
    return bools[pname];
    return NULL;
    //return rust::sim_get_param_bool(pname);
}

bx_param_string_c *bx_real_sim_c::get_param_string(const char *pname, bx_param_c *base)
{
    printf("get param %s\n", pname);
    return strings[pname];
}

extern "C" {
BOCHSAPI bx_param_enum_c* sim_new_param_enum(const char *name, const char **values,
        Bit32u idx)
{
    return new bx_param_enum_c(
            NULL,
            name,
            NULL,
            NULL,
            values,
            idx,
            0
    );
}

BOCHSAPI void sim_delete_param_enum(bx_param_enum_c *e) {
    delete e;
}

BOCHSAPI bx_param_num_c* sim_new_param_num(const char *name, Bit64u min, Bit64u max,
        Bit64u val)
{
    return new bx_param_num_c(
            NULL,
            name,
            NULL,
            NULL,
            min,
            max,
            val
    );
}

BOCHSAPI void sim_delete_param_num(bx_param_num_c *n) {
    delete n;
}

BOCHSAPI bx_param_bool_c* sim_new_param_bool(const char *name, bool val)
{
    return new bx_param_bool_c(
            NULL,
            name,
            NULL,
            NULL,
            val
    );
}

BOCHSAPI void sim_delete_param_bool(bx_param_bool_c *b) {
    delete b;
}

BOCHSAPI bx_param_string_c* sim_new_param_string(const char *name, const char *val, unsigned max_sz)
{
    return new bx_param_string_c(
            NULL,
            name,
            NULL,
            NULL,
            val,
            max_sz
    );
}

BOCHSAPI void sim_delete_param_string(bx_param_string_c *b) {
    delete b;
}

}
void icp_init_params() {
    char const *model_values[] = {
        "bx_generic",
        "pentium",
        "pentium_mxx",
        "amd_k6_2_chomper",
        "p2_klamath",
        "p3_katmai",
        "p4_willamette",
        "core_duo_t2500_yonah",
        "atom_n270",
        "p4_prescott_celeron_336",
        "athlon64_clawhammer",
        "athlon64_venice",
        "turion64_tyler",
        "phenom_8650_toliman",
        "core2_penryn_t9600",
        "corei5_lynnfield_750",
        "corei5_arrandale_m520",
        "corei7_sandy_bridge_2600k",
        "zambezi",
        "trinity_apu",
        "ryzen",
        "corei7_ivy_bridge_3770k",
        "corei7_haswell_4770",
        "broadwell_ult",
        "corei7_skylake_x",
        "corei3_cnl",
        "corei7_icelake_u",
        "tigerlake",
        NULL
    };
    enums["cpu.model"] = sim_new_param_enum ("model", model_values, 27);

    char const *apic_values[] = {
        "legacy",
        "xapic",
        "xapic_ext",
        "x2apic",
        NULL
    };
    enums["cpuid.apic"] = sim_new_param_enum ("apic", apic_values, 3);

    char const *simd_values[] = {
        "none",
        "sse",
        "sse2",
        "sse3",
        "ssse3",
        "sse4_1",
        "sse4_2",
        "avx",
        "avx2",
        NULL
    };
    enums["cpuid.simd"] = sim_new_param_enum ("simd", simd_values, 8);

    strings["cpu.msrs"] = sim_new_param_string("msrs", "" , 1);
    strings["cpuid.brand_string"] = sim_new_param_string("Intel(R) Core(TM) i7-7800X CPU @ 3.50GHz\0\0\0\0\0\0\0\0", "", 1);

    bools["cpuid.mmx"] = sim_new_param_bool("mmx", true);
    bools["cpuid.sse4a"] = sim_new_param_bool("sse4a", true);
    bools["cpuid.misaligned_sse"] = sim_new_param_bool("misaligned_sse", true);
    bools["cpuid.sep"] = sim_new_param_bool("sep", true);
    bools["cpuid.xsave"] = sim_new_param_bool("xsave", true);
    bools["cpuid.xsaveopt"] = sim_new_param_bool("xsaveopt", true);
    bools["cpuid.aes"] = sim_new_param_bool("aes", true);
    bools["cpuid.sha"] = sim_new_param_bool("sha", true);
    bools["cpuid.adx"] = sim_new_param_bool("adx", true);
    bools["cpuid.x86_64"] = sim_new_param_bool("x86_64", true);
    bools["cpuid.x87"] = sim_new_param_bool("x87", true);
    bools["cpuid.fsgsbase"] = sim_new_param_bool("fsgsbase", true);
    bools["cpuid.pcid"] = sim_new_param_bool("pcid", true);
    bools["cpuid.smep"] = sim_new_param_bool("smep", true);
    bools["cpuid.smap"] = sim_new_param_bool("smap", true);

    bools["cpuid.mwait"] = sim_new_param_bool("mwait", false);
    bools["cpuid.movbe"] = sim_new_param_bool("movbe", false);
    bools["cpuid.1g_pages"] = sim_new_param_bool("1g_pages", false);
    bools["cpuid.avx_f16c"] = sim_new_param_bool("avx_f16c", true);
    bools["cpuid.avx_fma"] = sim_new_param_bool("avx_fma", true);
    bools["cpuid.fma4"] = sim_new_param_bool("fma4", false);
    bools["cpuid.xop"] = sim_new_param_bool("xop", false);
    bools["cpuid.tbm"] = sim_new_param_bool("tbm", false);

    bools["cpu.cpuid_limit_winnt"] = sim_new_param_bool("cpuid_limit_winnt", false);
    bools["cpu.ignore_bad_msrs"] = sim_new_param_bool("ignore_bad_msrs", false);
    // this needs to be set to false] = because the reset path calls DEV_cmos_get_reg(0x0f,
    // which segfaults as I haven't implemented that stub yet...
    bools["cpu.reset_on_triple_fault"] = sim_new_param_bool("reset_on_triple_fault", false);
    bools["cpu.ignore_bad_msrs"] = sim_new_param_bool("ignore_base_msrs", true);
    bools["keyboard_mouse.mouse.enabled"] = sim_new_param_bool("mouse_enabled", false);
    
    nums["cpu.n_threads"] = sim_new_param_num("n_threads", 1, 4, 1);
    nums["cpu.n_cores"] = sim_new_param_num("n_cores", 1, 8, 1);
    nums["cpu.n_processors"] = sim_new_param_num("n_processors", 1, 1, 1);
    nums["cpu.quantum"] = sim_new_param_num("quantum", 1, 32, 16);

    nums["cpuid.level"] = sim_new_param_num("level", 5, 6, 6);
    nums["cpuid.vmx"] = sim_new_param_num("vmx", 0, 2, 2);
    nums["cpuid.bmi"] = sim_new_param_num("bmi", 0, 2, 2);

    // cannot find values for these vvv
    nums["cpuid.stepping"] = sim_new_param_num("stepping", 0, 0, 0);
    nums["cpuid.model"] = sim_new_param_num("model", 0, 0, 0);
    nums["cpuid.family"] = sim_new_param_num("family", 0, 6, 6);
    
    nums["port"] = sim_new_param_num("port", 0, 0xFFFF, 1234);

    nums["text_base"] = sim_new_param_num("port", 0, 0xFFFF, 0);
    nums["data_base"] = sim_new_param_num("port", 0, 0xFFFF, 0);
    nums["bss_base"] = sim_new_param_num("port", 0, 0xFFFF, 0);
}



logfunctions *siminterface_log = NULL;
bx_list_c *root_param = NULL;
bx_simulator_interface_c *SIM = new bx_real_sim_c();

