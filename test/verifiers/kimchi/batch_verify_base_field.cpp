//---------------------------------------------------------------------------//
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_batch_verify_base_field_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
//#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fr.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/batch_verify_base_field.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fq.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"

#include "test_plonk_component.hpp"

// #include<fstream>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_batch_verify_base_field_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_batch_verify_base_field_test) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 25;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    constexpr static const std::size_t batch_size = 1;
    constexpr static const std::size_t eval_rounds = 5;
    constexpr static const std::size_t comm_size = 1;
    // constexpr static const std::size_t n_2 = ceil(log2(n));
    // constexpr static const std::size_t padding = (1 << n_2) - n;

    constexpr static std::size_t public_input_size = 32;
    constexpr static std::size_t max_poly_size = 32;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 5;

    constexpr static std::size_t srs_len = 32;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

    constexpr static const std::size_t bases_size = kimchi_constants::final_msm_size(batch_size);

    using component_type = zk::components::batch_verify_base_field<ArithmetizationType,
                                                                   curve_type,
                                                                   kimchi_params,
                                                                   commitment_params,
                                                                   batch_size,
                                                                   0,
                                                                   1,
                                                                   2,
                                                                   3,
                                                                   4,
                                                                   5,
                                                                   6,
                                                                   7,
                                                                   8,
                                                                   9,
                                                                   10,
                                                                   11,
                                                                   12,
                                                                   13,
                                                                   14>;

    using opening_proof_type =
        typename zk::components::kimchi_opening_proof_base<BlueprintFieldType, commitment_params::eval_rounds>;
    using commitment_type =
        typename zk::components::kimchi_commitment_type<BlueprintFieldType,
                                                                commitment_params::shifted_commitment_split>;

    // using transcript_type = kimchi_transcript_fq<ArithmetizationType, CurveType,
    //                                 W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10,
    //                                 W11, W12, W13, W14>;

    using binding = typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>;

    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using batch_proof_type = typename zk::components::
        batch_evaluation_proof_base<BlueprintFieldType, ArithmetizationType, kimchi_params, commitment_params>;

    // zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

    std::size_t row = 0;

    std::cout << "FINAL MSM SIZE(bases_size): " << bases_size << std::endl;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type H;
    H.X = 0x092060386301C999AAB4F263757836369CA27975E28BC7A8E5B2CE5B26262201_cppui256;
    H.Y = 0x314FC4D83AE66A509F9D41BE6165F2606A209A9B5805EE85CE20249C5EBCBE26_cppui256;

    public_input.push_back(H.X);
    public_input.push_back(H.Y);

    var_ec_point H_var = {var(0, row++, false, var::column_type::public_input),
                          var(0, row++, false, var::column_type::public_input)};
    
    const std::size_t G_len = 32;
    std::array<curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type, G_len> G;

    G[0].X = 0x121C4426885FD5A9701385AAF8D43E52E7660F1FC5AFC5F6468CC55312FC60F8_cppui256;
    G[0].Y = 0x21B439C01247EA3518C5DDEB324E4CB108AF617780DDF766D96D3FD8AB028B70_cppui256;
    G[1].X = 0x26C9349FF7FB4AB230A6F6AEF045F451FBBE9B37C43C3274E2AA4B82D131FD26_cppui256;
    G[1].Y = 0x1996274D67EC0464C51F79CCFA1F511C2AABB666ABE67733EE8185B71B27A504_cppui256;
    G[2].X = 0x26985F27306586711466C5B2C28754AA62FE33516D75CEF1F7751F1A169713FD_cppui256;
    G[2].Y = 0x2E8930092FE6A18B331CE0E6E27B413AA18E76394F18A2835DA9FAE10AA3229D_cppui256;
    G[3].X = 0x014B2DB7B753A74D454061FCB3AC537E1B4BA512F9ED258C996A59D9DACD13E5_cppui256;
    G[3].Y = 0x06F392D371494FC39174C4B70C692B96F3B7C42DA288F6B7AABF463334A952D0_cppui256;
    G[4].X = 0x12CA0E2DBF286021CB76B7C12B6C9AD7FDF1D05F722F6EF14BD43E53E7B92120_cppui256;
    G[4].Y = 0x216A80B79D3995D1F39CE19855C475052D1148ACBDD379FE98961BFBD0A3E428_cppui256;
    G[5].X = 0x1D257C1F4EC9872C9E06549BC910F7B7196F2E7CB120AEC3FDCEB049C7A0C9A5_cppui256;
    G[5].Y = 0x191CBEC20ED5EA342B6B395E92996215F7D93C675DA56A13D548EFB58524D336_cppui256;
    G[6].X = 0x06236026ED7DC19C44540FBAF0C1C3498F82880A34422547FFF519FFF744BB48_cppui256;
    G[6].Y = 0x3A02C5410DABDE160BD09232A14F00B1EF6CD4D6285C90A8D41FA00BFF922F0A_cppui256;
    G[7].X = 0x079333FDE60D3F670068B5A1D486EDDD87DDF91D1E1FC000F387991B4ED848B4_cppui256;
    G[7].Y = 0x3F7FC1A39FD74BDEDC129195080D298CFC2C2CF714BAD9F9334F0DAFB035C200_cppui256;
    G[8].X = 0x069B398C2968553B7987FF840CF0B71359D10F249F08C40898550A63F196D856_cppui256;
    G[8].Y = 0x1B68BB879D6EC4EFAA2207E212B59BAD0D8E5E2493F99BE3F2F24764046CD277_cppui256;
    G[9].X = 0x2CBD65973AE0BE0B9E652CEC35EFE509E1FA8DD8349DC1E644DB494DC2B4FD75_cppui256;
    G[9].Y = 0x1E27B8178E720407694F4EA1413B0CB87AF4058CB308BBD68FF42D5078DE243E_cppui256;
    G[10].X = 0x0F29A22EF6949DE85427F72CCD04E3F8F56837BB56DA17D8FA5DE9025E6B9ED5_cppui256;
    G[10].Y = 0x26A2CD91BD2771E20DECAACDC6CA96E7759668F3D0B7E8810866D27737627A59_cppui256;
    G[11].X = 0x300EE47C831AB28067BFE9364A819C894FA02155C5FC3E94E83A0EAD3110E9E5_cppui256;
    G[11].Y = 0x2D4FD253E12958FD548AC51E62F3158EB3EE8CB10F148F0A44D2C6E562D632CA_cppui256;
    G[12].X = 0x2A9EA5BCE9D10ED951E11E4DE64DED939D1FC6B5DE07DFF33D49861B7DE2EE71_cppui256;
    G[12].Y = 0x0708F926C80F2A68C3F59C8C25D26F29FF90842A7C1BEDE0B1801D7DF258077B_cppui256;
    G[13].X = 0x2DEA83FC8EA7A9727A5F2184EDCBF6A17083C10DACE4F45DADB330CE1624DC8B_cppui256;
    G[13].Y = 0x02DE1252440BF67F0B7A40DE4B7D9157993CE1D0DC47F8D4B3BCF126FBE00E2B_cppui256;
    G[14].X = 0x341DE1D9B175235F492C6DAD8580443D11B12DF39EE95D497935BFF99D4E775F_cppui256;
    G[14].Y = 0x01177651EA542F5402CA5B075C5A2082F5F4EE1D3B054FC97CF7D30758D89841_cppui256;
    G[15].X = 0x37D2BB9884B41B3125444D81C59E8EDA167284FB5D637C9D54B21753830F14A0_cppui256;
    G[15].Y = 0x0D5708EB79051B4704EDB309CDFCA38030CD8B656A5C9051B5C1AFA6B1C30D46_cppui256;
    G[16].X = 0x026A67515EF102D65C7694144B457240C4E3270A0240640A5EAF9B3E7489C54E_cppui256;
    G[16].Y = 0x1B78FD66A3E4A168D0CEC1846F03B1624342491857F9204743A44DE2E90A42E2_cppui256;
    G[17].X = 0x2E2489CBFD8534059574AACD43C137788C54D86B1292CF4B17850EE95F913198_cppui256;
    G[17].Y = 0x10D13EAD8E28E1493325B7DBB89025DA06A8867EE60BCADD1D794A847D871A46_cppui256;
    G[18].X = 0x3FB39F7B1DBD63694D40FC6C105FBD8242908DB2CF82B5F0FACE46A7792CC0A0_cppui256;
    G[18].Y = 0x01DF2D8291BAA5ECFF544683F16F36D8C83078DFD24B5C8C93DFEDA524704750_cppui256;
    G[19].X = 0x39DA705C7CD47D34F9B2E2A7F57200F656A229398E7A0F89A5534D72C8BAA2C7_cppui256;
    G[19].Y = 0x1C5E177C851121F1A90AC844245B7D7D5512C822ABF4AF37213AF5B2EBCED4F0_cppui256;
    G[20].X = 0x0A35295A58443F71E676CE42BA6FC44D4EF1DEB8E9E9C7D537CE4CD453576521_cppui256;
    G[20].Y = 0x3600DA2E2E5D3674E13613871FA8B9A5D96F905DD69114FBF3F69F61D0C57263_cppui256;
    G[21].X = 0x2879FDC5D79EC2FD73D8776DD5ED76F8BC6DA10D4501AA892D11CC02152E33C5_cppui256;
    G[21].Y = 0x06FC48C9C7CF8B4CD94812DC8EE2ABBC4A0775D52E01097E6877F2A1A7547786_cppui256;
    G[22].X = 0x0A3499DB18871CBF14818C2D5152742B4457FDF30DF5936172EDE2FE9A537701_cppui256;
    G[22].Y = 0x0548D846722829A12B1C9C39411DE0AC8C5C2F97C1953432DF60251E0DAE91B2_cppui256;
    G[23].X = 0x25A8F59C1D7C23576952D07640231EEBDE39D9F89BB85110966096D36043DB0A_cppui256;
    G[23].Y = 0x0F6EB10365B419FA5179D3278BC7F834D27AD930AE11674FFC5F00549556DBB8_cppui256;
    G[24].X = 0x1F4A67F9C220741648FBACFAC1934B09C3E903EFBE12DECFA6820656D3778DAA_cppui256;
    G[24].Y = 0x3685316B926A7C4351AB8AB802174B11BF8EBD5999989F0343555D9575CFA3CC_cppui256;
    G[25].X = 0x1ECC9BE71F9ACF900FA6CDCC452550C7991BFC25258CEFACBCF51D541DF2D819_cppui256;
    G[25].Y = 0x0FBDFA76ACB83F9C4DF9337FEC47F38672D31E9EB5406034812E5C21C6494BDD_cppui256;
    G[26].X = 0x2E79A282F86F8FC1B2DB59443975544DD7C92883322C82C2C283DC51A0E34825_cppui256;
    G[26].Y = 0x0118E6A449918C38AA0D290373F1D605DC21B6B5F228C41BFF596C635AF7761E_cppui256;
    G[27].X = 0x3FCD47170790B2A3E85CEAEE44940DACA0E11DD132960092FB2E1613B364849B_cppui256;
    G[27].Y = 0x2859254A7ABFB288138B64009A85178250FD120351634CCD41D9ECE993D9F6A3_cppui256;
    G[28].X = 0x1A29CFD3AF8F7C0F19861362DAC9FD8034F82C2C1750A425B446461B5BC63E4B_cppui256;
    G[28].Y = 0x15E12C10AE7FFF431F6FAAB8EE607386AA85EB7AFB806E264B8952D51404E17D_cppui256;
    G[29].X = 0x2EECD04E0E37FAF9C51C61249470F118C5C5EA8E6DDB4B645F99C47D3BA07F68_cppui256;
    G[29].Y = 0x33E6418DD36692F7EE870BB3577115F87D62E9D257374950A17A3B0154B8B35D_cppui256;
    G[30].X = 0x3BADB4DCEADF739775588552805A959B7D216BFD86847BA54D662B777B2B1FCF_cppui256;
    G[30].Y = 0x0CB8DEE5BE3197C76685F25D4596C766A2DA3542BD89FD9633D7590EA2B68FD0_cppui256;
    G[31].X = 0x3FC5DE9E2422625B53D18E55C069CBCEC9C2D2C4F8DAB5B1BC11D3702F3F5E22_cppui256;
    G[31].Y = 0x0EE46C6ABF41C33D66B60AA4E508CE43DFE02535EF19E158AB66B49D12BD171F_cppui256;

    std::array <var_ec_point, G_len> G_var;
    for (std::size_t i = 0; i < G_len; i++) {
        public_input.push_back(G[i].X);
        public_input.push_back(G[i].Y);
        G_var[i] = {var(0, row++, false, var::column_type::public_input),
                          var(0, row++, false, var::column_type::public_input)};

    } 

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type op_proof_g;
    op_proof_g.X = 0x34B0922BBBA14A38511A526791111C8844E3A174B578D1D334BCB77FEB2295C0_cppui256;
    op_proof_g.Y = 0x3A21685332DF86AA639E2C47975969A37AAD595A918900029F55F772C6E4BEA3_cppui256;

    public_input.push_back(op_proof_g.X);
    public_input.push_back(op_proof_g.Y);

    var_ec_point op_proof_g_var = {var(0, row++, false, var::column_type::public_input),
                          var(0, row++, false, var::column_type::public_input)};

/*
    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type shifted =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(shifted.X);
    public_input.push_back(shifted.Y);

    var_ec_point shifted_var = {var(0, row++, false, var::column_type::public_input),
                                var(0, row++, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type unshifted = algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(unshifted.X);
    public_input.push_back(unshifted.Y);

    var_ec_point unshifted_var = {var(0, row++, false, var::column_type::public_input),
                                  var(0, row++, false, var::column_type::public_input)};

    curve_type::base_field_type::value_type f_zeta = algebra::random_element<curve_type::base_field_type>();

    public_input.push_back(f_zeta);

    var f_zeta_var = var(0, row++, false, var::column_type::public_input);

    curve_type::base_field_type::value_type f_zeta_w = algebra::random_element<curve_type::base_field_type>();

    public_input.push_back(f_zeta_w);

    var f_zeta_w_var = var(0, row++, false, var::column_type::public_input);

*/


    std::array<var_ec_point, eval_rounds> L_var;
    std::array<var_ec_point, eval_rounds> R_var;
    
    std::array<curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type, eval_rounds> L_value;
    std::array<curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type, eval_rounds> R_value;

    L_value[0].X = 0x0FE767E47FF2C0F6B315C1B2493B40F4626FA76841111BC19D4052D3B8734969_cppui256; // rust generic
    L_value[0].Y = 0x13FEAE182094F99A3C0648AF0AC2B183B038E89883CF3742AC99915F300739FD_cppui256;
    R_value[0].X = 0x2F3518E815AB0295742B75680CA58BF9E1E9DA5F951B9D8F041D66FB889005C8_cppui256;
    R_value[0].Y = 0x2543E675A4B57C5F007164FD3839706E4B65FA2545335AFCAF22D79553FD6724_cppui256;
    L_value[1].X = 0x3ECF24DAAA7E0717E21B678E25FEA1DD926CA9D229275691C34EC64E325EC45E_cppui256;
    L_value[1].Y = 0x08CEBD461644562EE9AC25B12B2CA7D9D4CE30079C725F06CF3D3305ED6E1654_cppui256;
    R_value[1].X = 0x3F446EF8DB845A4C20CB230F3D40CA9E2047666E264765034B8BBEE92F38DACF_cppui256;
    R_value[1].Y = 0x3A6C44D5B0E0AC008249F737103DB5B8E62E91466624635CE037148CA199AE33_cppui256;
    L_value[2].X = 0x1E2F6E0C6B66A82651252B1D59B3E87FBD6CE135BAE8AB2A3EDE64AC0F634C07_cppui256;
    L_value[2].Y = 0x2060EBA72A27490D75E85A043050C0802C194B1C947A75A5000673CEBC76352B_cppui256;
    R_value[2].X = 0x0D12D51C6B1FFC454A6004D0C5DB735EC954BF17A5051A9DFF7201C51EF18371_cppui256;
    R_value[2].Y = 0x2262497FA64CC2464B5EE41ABAED487A6915F7A688DDADFA0E3F2872007A0DAB_cppui256;
    L_value[3].X = 0x28F3980FF9EEBDF08CFC574802DB0813697BF3C12DE6B10E1796CB7D1E7C5592_cppui256;
    L_value[3].Y = 0x157DEBC2BADC29D4FD571120192415673DD8DEB6810A17F3B96806B575A9D7AD_cppui256;
    R_value[3].X = 0x2182E7FD21B3910CDBC27DF4FD717ADEEA2938134ADA7EC57FDE36759C93FA3A_cppui256;
    R_value[3].Y = 0x29DADAE664E28DADCFBD1A0C0E87B93FFE29E1E32DDBC118FB9417BED97F7CA4_cppui256;
    L_value[4].X = 0x2761BAFF6B47CB1BF326DDFC5B7F65EBA27956C3F6186DB6558BF4122A90A7DD_cppui256;
    L_value[4].Y = 0x348BC6EE5DB80A2AD0B9326821CEA755990F678CE754FD03AD0553A7E8FCC8C3_cppui256;
    R_value[4].X = 0x23F299C6D1D8B38CC626461B0BF37122A8ADD1919779A5503E28E8B9AC437CCB_cppui256;
    R_value[4].Y = 0x334FEE4240F1A6B0196C303ED2C11C11B203D2C9FC1A59B6D8A40C679A06C139_cppui256;




    for (std::size_t i = 0; i < eval_rounds; i++){
        public_input.push_back(L_value[i].X);
        public_input.push_back(L_value[i].Y);
        public_input.push_back(R_value[i].X);
        public_input.push_back(R_value[i].Y);

        L_var[i] = {
            var(0, row++, false, var::column_type::public_input),
            var(0, row++, false, var::column_type::public_input)
        };

        R_var[i] = {
            var(0, row++, false, var::column_type::public_input),
            var(0, row++, false, var::column_type::public_input)
        };
    }

    // 25 comms
    const std::size_t comm_len = 25;
    std::array<curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type, comm_len> comm;

    comm[0].X = 0x0A1AA1674BFA26CFB9D1F7CC37009E04761528998A39DDDC7107069FEA2B499B_cppui256;
    comm[0].Y = 0x2E8576AEF5BC8C640EEC13787D66B2A6B10CD33523BEECDF63FC083719EC5913_cppui256;
    comm[1].X = 0x249C6F5211DB7B3E58E8C25EA91A4EDE423B32B646B526E0C8A18A7565D70CAB_cppui256;
    comm[1].Y = 0x17DC1532F20E409645D114C7E76FBD0DF6D67DA8BE1235F2F48FADACE4BA674D_cppui256;
    comm[2].X = 0x085220F8668A7789843F474CA2AC22C37D8B8683257D13674EFB206A360D0AF6_cppui256;
    comm[2].Y = 0x3A30BC2478885903A20DEB3140488E871F65A68F2FAED91731D5290381D739F1_cppui256;
    comm[3].X = 0x2C6F8B6283E14B33E46FDC037D2A1968D64F2997BDAA06BF37A9705CC226CB8D_cppui256;
    comm[3].Y = 0x2369178903473D322DD459F00BB7A3605203522FEA658590259B8FB1FE66E65D_cppui256;
    comm[4].X = 0x3094763C768A2D4DA47EA2BA3F39D984FCE447C2B756337E18BC8837661808F8_cppui256;
    comm[4].Y = 0x081B5C28090094E4401F4666BBF4899057C28962A6B64E058C5634FB9E33D7AB_cppui256;
    comm[5].X = 0x3192023079E85298F67CC2BB7F0B56D61F44F10E522EEF9B2D6B6BA90C6C65C0_cppui256;
    comm[5].Y = 0x1DF861AA4D36146CFF7A4FA936DB7EB7B0B06992E659E74AC304C38B14365C4B_cppui256;
    comm[6].X = 0x2B48A334B091399ABC3FFA65F50FCF06849F2517F9E25DE2BB2BCA994501C236_cppui256;
    comm[6].Y = 0x03EF798F0EFECD95271561DF5C34C1F2C443D480AAC657EC9DADF501BF1BCAB1_cppui256;
    comm[7].X = 0x2A3C0B5C38F86E92F364CD1E98B90DC29805BDD44074831D590ADB11DC284C8D_cppui256;
    comm[7].Y = 0x080A9EBFF2C187C037CAAD489F341E1603AA2D9ACD11CEC90A75BAC1D9D91D27_cppui256;
    comm[8].X = 0x1E896D431EC84925730585ECC0C6ACEC1D2D210C73A4232DB96CC9243E3FD2B0_cppui256;
    comm[8].Y = 0x22C09EE2380A4996EA2033BDB44CA47E2192B02C3C614B21807969D62DA885E8_cppui256;
    comm[9].X = 0x013B1B5426005CE14847A24007E4C84F1EEE9FE99A6BE5618E1112C5B7BD4833_cppui256;
    comm[9].Y = 0x3ADA5E8C36CA00DAD374675854BBCE646902C66B4575772F27056E122EB4FB76_cppui256;
    comm[10].X = 0x0B1D36795958F1AF584E7D839FC5AB0932B341C873A8F14E4CC7C0DBC60E14C0_cppui256;
    comm[10].Y = 0x26A4699FEC12BC3F28E09D9383083BC6E8DCC6160244BB2ACC615BD526676430_cppui256;
    comm[11].X = 0x1E143FB20689F774780EFAD9E198FFA0F82930E90282022853E86959D4524990_cppui256;
    comm[11].Y = 0x2F0828603D6A58821F43D2F0DE75EB992849F2FDCB33C854BFD9CC00F038B29B_cppui256;
    comm[12].X = 0x2453FAA0ED474210B25D1131D075963DFF2086F3993902F50280B078C054DC22_cppui256;
    comm[12].Y = 0x06695D5D68BB67E5314B84233CE09DAAE998EDE03A711A8CB9D9C8FF72359304_cppui256;
    comm[13].X = 0x19BCD57208BCF2CB94D9AD7C04DDD0AEDAE680DF5C160CC41FCAB6322E2922B5_cppui256;
    comm[13].Y = 0x014DB3B97C439C25B5F265F277143C8030014DF3AFCA6153BC86197415D8E74D_cppui256;
    comm[14].X = 0x330CE397F026A466E89DA13F31525978A8BE2604EFC1954D64FA989DA3A0A515_cppui256;
    comm[14].Y = 0x3EC89B71C0FE64E1517C5E91D2F722577A6EA18A262E37DE1A5BCBBE3DA39C0D_cppui256;
    comm[15].X = 0x1550CEF977AFB848630EADAA5D1109961C980C026CCDAECBCDCE65D44A686ACA_cppui256;
    comm[15].Y = 0x343FB3192B5E16C468749EA87DA2AFAB02EA6D8B84EE4DBE3D501AD7720F1A5A_cppui256;
    comm[16].X = 0x118D4542A95F64F628A18897F1618F6FBA930BB69E2211FE6B87D7D57964E515_cppui256;
    comm[16].Y = 0x09BED30175068832797E00D54C9C41FD20B95CE7C85772D7A88F7CB0EC21205E_cppui256;
    comm[17].X = 0x3EA9A0A449F3D480AAB91D16966928C9333A51498673CB8DC2D2C4BE45C60529_cppui256;
    comm[17].Y = 0x315750C943269EE304319CF5EADE5CF89CB119E614D3558A9268151CBDDA0CF1_cppui256;
    comm[18].X = 0x3F10748D4451468AA1EBB78CDE1167A734F22AF23C66F2F6C123F77C19D0D040_cppui256;
    comm[18].Y = 0x353598903C926F9EFD8F0212EDA038ED7A92E3ABA1294963E4ABFBA269C1EE3A_cppui256;
    comm[19].X = 0x26C9349FF7FB4AB230A6F6AEF045F451FBBE9B37C43C3274E2AA4B82D131FD26_cppui256;
    comm[19].Y = 0x1996274D67EC0464C51F79CCFA1F511C2AABB666ABE67733EE8185B71B27A504_cppui256;
    comm[20].X = 0x35AF80504B4DBF58CE3535F3E159BD407695088EFBF1EF56D4597A7F1CBEF531_cppui256;
    comm[20].Y = 0x2D36B9BCB23702DF2F4A2C9E60ABBB81C2BE261D227AF025DDDE4FFF354727CB_cppui256;
    comm[21].X = 0x1CFDC82F8279850B957D0BDE2A188AD5060D80A97EF8B4E56CD17CFE1067CBD9_cppui256;
    comm[21].Y = 0x2863D1D7D5EFC2155B2BCCB849B6EA6738E2705A4DC63115045B797E2CFA6511_cppui256;
    comm[22].X = 0x262ABA0787800EF4CBD18688A534659AB77861C373006A4E0E42BC06D85F9E79_cppui256;
    comm[22].Y = 0x150A55D182F3B621B10774BD11C8B8198048DEE7C535DDD08992B41928E45DC3_cppui256;
    comm[23].X = 0x0C51759D046C2382B5800C5CAA9D9DF74636E1FE0671DF237CD2AC771D56436D_cppui256;
    comm[23].Y = 0x39AE43E4BE7084DB9EFDCA61204B29929A2C242605FEFE95F41F0D5DD286DA38_cppui256;
    comm[24].X = 0x18819B168F851F614CF0DD2F4C30030C1267688C1723BF68293324770AB41DE3_cppui256;
    comm[24].Y = 0x1E03B384B597E7A9F17F1B7E36A0B1179291AD17F30C8871379318BADEC65C8C_cppui256;
    


    std::array <var_ec_point, comm_len> comm_var;
    for (std::size_t i = 0; i < comm_len; i++) {
        public_input.push_back(comm[i].X);
        public_input.push_back(comm[i].Y);
        comm_var[i] = {var(0, row++, false, var::column_type::public_input),
                          var(0, row++, false, var::column_type::public_input)};

    } 


    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type delta =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    delta.X = 0x3F1F9C19762555AA9C685C09DBF1F3A3125CDB1D673B2CB540A3B1DD840CF8E3_cppui256; // rust generic
    delta.Y = 0x282438D65ABA871BB983856B1C1CF98131C543128736E3E46D625268F48E9D03_cppui256; // rust generic

    public_input.push_back(delta.X);
    public_input.push_back(delta.Y);

    var_ec_point delta_var = {var(0, row++, false, var::column_type::public_input),
                              var(0, row++, false, var::column_type::public_input)};

/*
    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type G =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(G.X);
    public_input.push_back(G.Y);

    var_ec_point G_var = {var(0, row++, false, var::column_type::public_input),
                          var(0, row++, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type H =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(H.X);
    public_input.push_back(H.Y);

    var_ec_point H_var = {var(0, row++, false, var::column_type::public_input),
                          var(0, row++, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type PI_G =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(PI_G.X);
    public_input.push_back(PI_G.Y);

    var_ec_point PI_G_var = {var(0, row++, false, var::column_type::public_input),
                             var(0, row++, false, var::column_type::public_input)};

    std::array<curve_type::base_field_type::value_type, bases_size> scalars;

    std::array<var, bases_size> scalars_var;

    typename BlueprintFieldType::integral_type aa;
    typename BlueprintFieldType::integral_type bb;
    typename BlueprintFieldType::integral_type cc;
    typename BlueprintFieldType::integral_type dd;

    std::ifstream file("./input.txt");
        if (file) {
            std::cout << "FILE == TRUE" << std::endl;

    for (std::size_t i = 0; i < bases_size; i++) {
        scalars[i] = algebra::random_element<curve_type::base_field_type>();
        
        unsigned long a, b, c, d;
        
            // while (true) {
                file >> a >> b >> c >> d;
            //     if (file.eof()) {
            //         break;
            //     }

            aa = a;
            bb = b;
            cc = c;
            dd = d;

            /*
            std::cout << "a = " << a << std::endl;
            std::cout << "b = " << b << std::endl;
            std::cout << "c = " << c << std::endl;
            std::cout << "d = " << d << std::endl;
            std::cout << std::endl;
            std::cout << "b << = " << (bb <<  64) << std::endl;
            std::cout << "c << = " << (cc << 128) << std::endl;
            std::cout << "d << = " << (dd << 192) << std::endl;
*/ /*
            scalars[i] = aa + (bb <<  64) + (cc << 128) + (dd << 192);
            

            // std::cout << "\n\n\n " << scalars[i].data << std::endl;
            // }
        


        public_input.push_back(scalars[i]);
        scalars_var[i] = var(0, row + i, false, var::column_type::public_input);
    }
    } */


    std::array<curve_type::scalar_field_type::value_type, bases_size> scalars;

    std::array<var, bases_size> scalars_var;

    scalars[0] = 0x0D9A3B23A66EE3D3BF40B67D4EDCAEB5C14A625C025CABAD63E13D291AD5CB2E_cppui256;
scalars[1] = 0x0000000000000000000000000000000000000000000000000000000000000001_cppui256;
scalars[2] = 0x0F97DC26288ABE63FBF2A6951997A9291C344FC18C1BACE8384995871DBBC0C5_cppui256;
scalars[3] = 0x2E8721D78436F8DB814A82F084043F71EDD94F75C51382DE7D383DC1E95F9DAD_cppui256;
scalars[4] = 0x0E18B07BC7DF567DE83C02426FB62F0E1A939AE4CF39FB6AE00E6D6837E3DCA0_cppui256;
scalars[5] = 0x283FD297BE1A344D7438EC7FD7CB9CAC5DD52241B8FF5A27F544546BBC398536_cppui256;
scalars[6] = 0x3B6DBEF55D2E6BB81364A9755D2046DD25629E95C587B1C48D95CD0DC3791AB1_cppui256;
scalars[7] = 0x1AB2EF2E496BB0105F574584CAB5189C38520997B7C6BB2C18D944900B85EA79_cppui256;
scalars[8] = 0x07ACDC93DBF29F071A11A8B663DD575D483937645A4DDCA814A62DE577EE6436_cppui256;
scalars[9] = 0x05B907E58584BF72EF7858B36A58E17E3A601809A6A6E27ECAE3F486E2474872_cppui256;
scalars[10] = 0x2D25EA0A9D26A1C8B154B4AFD688B6B291B4FF626C51FB4C17D27B5BEFE9DAEE_cppui256;
scalars[11] = 0x0DE5A45944BF93FEF1D746E13825BAB7749E9D7533DFF51B66521E0B99512384_cppui256;
scalars[12] = 0x00EBF659371226AC769B875187BF6E2D9FE850A914918C890DDF6D23689359C7_cppui256;
scalars[13] = 0x03A1650235271EEEAAD3BA831AD588586C282517B2CC6B59A36803FBC444C9C1_cppui256;
scalars[14] = 0x04A3F687CA8F525BAADBD71387B7B7879BB6A42D51A01A4B04030A15BE0D0206_cppui256;
scalars[15] = 0x13E1E1BAA791FEC6E326273D273F50A2558663032C4802BB3CAB20EE6D6467F4_cppui256;
scalars[16] = 0x001D1A10EDBDBA90B52BC2D283E35B4916304364A4830B6F184ABC271DAA87CB_cppui256;
scalars[17] = 0x118723522B297FB440C754A9B75C0278C2923D96CB0C46563BE4188B7230AFB7_cppui256;
scalars[18] = 0x2837B538ABE53840848259FBA91E95C039DBF528DA716FB6F6EE10C37E4688B1_cppui256;
scalars[19] = 0x0DFFD1692A71557C4194B59CE88F9A86E6574EF0681A0C8B113456055AECC6E0_cppui256;
scalars[20] = 0x01F8251E97A3E6A0876D98C33B31055C9814807C8F9176B653C961DB2E843DBF_cppui256;
scalars[21] = 0x2E2029E669BF6C97C24C4C1469B4A95413F61CD3800F7848D87D1D3394BF29A5_cppui256;
scalars[22] = 0x3DF8F7E2CDCD38986AE83E7D55054713E969BC0FE13C95F668BCC0B64CF2D4F1_cppui256;
scalars[23] = 0x0248D03A148633A13D3F74B398BFAD67C5304B010BF82F76D85A954C1F879DBF_cppui256;
scalars[24] = 0x21D55A30E6A5C139359F31150880888A9E676FB15F5C312818D51DAF71B680CB_cppui256;
scalars[25] = 0x0CC30F9137F18FA88EB08C0BEB165C93077B9B3BAE4AF740590B534CB81FFD1B_cppui256;
scalars[26] = 0x31D33AD57E542CF07AA0135469535EB3EC3FE8FB3234A07BC42F2AA99D3AF2DA_cppui256;
scalars[27] = 0x158BF2C5AB44B06BC5A79C0C507F839C9145543F466BF8ADCE44A612D0C5CCF1_cppui256;
scalars[28] = 0x3F6B8D512873A106E9F1502E6A3B572ADF317EE4B6276ABA6E13DA1F71D4A788_cppui256;
scalars[29] = 0x3E4714797DA825FB5885B093E34CD303323F1FF0F095900D3537D3BD29920C73_cppui256;
scalars[30] = 0x3B85FD74289E39C276BEAE393A6301D22682BB014ACC2C1C6DBD46D87CD32D43_cppui256;
scalars[31] = 0x023983C0967724F588C8263131C7CE3BF307BC6753744D6526420B9DBA60E288_cppui256;
scalars[32] = 0x397EC2BFBF857F464E08FE7E6255DBC07A39C794595E11D213B97C83D18D36C5_cppui256;
scalars[33] = 0x16E465F80D73760DEB0438C1225D9A00189EC4C62A953746377A3DA3AB81D19F_cppui256;
scalars[34] = 0x2FD3512EEDE7AA1149EC433E72544C973AD832AE00E3415B9704F28AC3160A3E_cppui256;
scalars[35] = 0x3BEC141E437FC9DFCEE5A2046445B34BF2AF3DA5B4FB16B089CF90E39D2DBB0C_cppui256;
scalars[36] = 0x22DCCDE6CD3203A68C301EEB08A2E37FE93ECD54F776EC811DF89EFADE7FE20C_cppui256;
scalars[37] = 0x39318048CA857D7478A2A6DD3960C1805C93BEE595F4EA785EE72656B7765E2E_cppui256;
scalars[38] = 0x185F735577F1F40AF340E5002AE6689C8253853F31A167F5287B658D195E8F40_cppui256;
scalars[39] = 0x2D1A597BB74B88FF1EBDA386887D5242B5428D71554FF1277E3AEEB9CAC8A17B_cppui256;
scalars[40] = 0x19966718F8C3B5EEE9BAD394D746031BEEC5F358C1E3AA8DCF1852B586B864E0_cppui256;
scalars[41] = 0x243AC8BB8ACCA0FDC53FAFE2F3339E65FE1F403905C2740B52BF0D52B95CE610_cppui256;
scalars[42] = 0x3450FA14E13FE115D171EED4D31556761BF1888DF861DA9F7FB5825E225151D9_cppui256;
scalars[43] = 0x367E30C26B13411CE220B25A0D380410272B2C4A8F787FAF363D6810A7F1E53B_cppui256;
scalars[44] = 0x2430AF9AFCA2B02C3958473D7A936228B74C5F49BFC3460F69AC28300A3B49D2_cppui256;
scalars[45] = 0x137947EE70BE899B1CBDF1C25470C911B4DDF29E5FB6CE670B048DB6FB3CC459_cppui256;
scalars[46] = 0x1EB96F664A70ACE3EB8602E74DCD0BE1F9F354FABB366D08036A002FFD657419_cppui256;
scalars[47] = 0x37CC4C9BD3F68854931DFC583300FDD5082615E069745022D352D72BE045AB6E_cppui256;
scalars[48] = 0x3857B18DDCDC7B3F3BBEBE73772594E2B831E508406D07E477548F4A75673B41_cppui256;
scalars[49] = 0x27C3E1DCB43154E9F2745D2C062F04ACCF446B4088FFDC0B5A1C45D5693F4795_cppui256;
scalars[50] = 0x3B5AAD1EB34BAA1E82A923D472DF3129C9B1CCB49C1C12AFCAD74837A6972D7B_cppui256;
scalars[51] = 0x2B23E3B889275312C53AD7A6E64E574BDA0D963A9EE6B2F0607B3843CC952155_cppui256;
scalars[52] = 0x234A644280DD573FC49CAD8E27E835F74B660D7CA38D2E2D4BC82A40A5A0AF69_cppui256;
scalars[53] = 0x0D7CC6747272123C75F71FFB7AF5CC7CA2B65892921BCF11C6B1169AFC79535A_cppui256;
scalars[54] = 0x288A7EDF9876593931A37F1BD26229D24D25B2B818340440FC109338A72C9AA2_cppui256;
scalars[55] = 0x0C1CB26A7BF012C5B2A0A78B82EDA77F3C7FE44C99589A6DC36647070F7F8FC5_cppui256;
scalars[56] = 0x377A0998B6B3646D88BAF511BB2111F6C861E3B01806FA63DDDD329621A6B614_cppui256;
scalars[57] = 0x3A5AFCA4A57D8C9BD7F463C1E826C630B1050A744A9A4C38BAB76F51B9A3427C_cppui256;
scalars[58] = 0x2DBE16A9BAA7D2928D1F1A646B09DA62FEA1F6EB3E16ADC25028113047855844_cppui256;
scalars[59] = 0x1DB3AA18AB571DA83ACF797BE5164A0387FB19FB1A529711EC00BCF922065FAF_cppui256;
scalars[60] = 0x10B8444FADB4A7959EB694AEAAFD6B6697B6934928751C2F0268F34E8AD55063_cppui256;
scalars[61] = 0x1D6466CBF1156D0D22C8498ED954EFCBFF10A399EB6E1623E2B8F322C37B90AF_cppui256;
scalars[62] = 0x35F7DE56469C37D368DE14E434E34E8EF3BD21B58CD199CD2776B705E9EE2295_cppui256;
scalars[63] = 0x17A461F0935310547473D268DB10BDA9FACC4F43AFE403EE088CD419ECC7D653_cppui256;
scalars[64] = 0x2E2935EFFE240C0EB0B7C4FED8928E18893604118A82D3146D92A91299347AEC_cppui256;
scalars[65] = 0x07FD07123C8784737364F10BBC615750D96DD8E6CC81B396D1EDBC639D0CD018_cppui256;
scalars[66] = 0x351BB30EC8664173DE4736810518587DE18118D4693D3617E80B4C791FEF0169_cppui256;
scalars[67] = 0x16CEAEB7F165F3F64D42F22A7B048F5F3BEE61FA9EF99DDB96D199160A433F05_cppui256;
scalars[68] = 0x083AE1D4579A626C173C97EAE83025E157AFA4037C6E1B0C642FDF6C96DB7361_cppui256;
scalars[69] = 0x1E6152BF1DF287A2FEEEF609DAC75B222B5006F62AD528B30322B26D85867616_cppui256;
scalars[70] = 0x3AEEF37C30484AD5B55CF57303D716A0978D50EB2C32E811B08A02E91D5F743C_cppui256;
scalars[71] = 0x0000000000000000000000000000000000000000000000000000000000000001_cppui256;

    for (std::size_t i = 0; i < bases_size; i++) {
        curve_type::scalar_field_type::value_type base = 2;
        if ((scalars[i] != 1) & (scalars[i] != 0) & (scalars[i] != -1)){
            scalars[i] = (scalars[i] - base.pow(255) - 1) / 2;
        } else {
            scalars[i] = scalars[i] - base.pow(255);
        }

        typename curve_type::scalar_field_type::integral_type integral_scalar = typename curve_type::scalar_field_type::integral_type(scalars[i].data);
        typename curve_type::base_field_type::value_type base_scalar = integral_scalar;
        public_input.push_back(base_scalar);
        scalars_var[i] = var(0, row++, false, var::column_type::public_input);
    }

    curve_type::base_field_type::value_type cip_shifted = 0x0877E225F785892E118B95754A625F1D008505745AF6E4B174D07168343CB13A_cppui256;
    public_input.push_back(cip_shifted);
    var cip_var = var(0, row++, false, var::column_type::public_input);

    curve_type::base_field_type::value_type state0 = 0x08C6DB20754B2277C8D16895B976293798DD898B19D348D4CDA80AE41B836A67_cppui256;
    public_input.push_back(state0);
    var state0_var = var(0, row++, false, var::column_type::public_input);

    curve_type::base_field_type::value_type state1 = 0x11EF8F246F63C43E46E22BC179C7171A3F2A9776AC62E5C488C482403FB00E07_cppui256;
    public_input.push_back(state1);
    var state1_var = var(0, row++, false, var::column_type::public_input);

    curve_type::base_field_type::value_type state2 = 0x3A44A14684FEA941DA87BFF86D42E61EC587BB5F7A33DC36B2C5324416FA8715_cppui256;
    public_input.push_back(state2);
    var state2_var = var(0, row++, false, var::column_type::public_input);



    // commitment_type comm_var = {{unshifted_var}};

    opening_proof_type o_var = {L_var, R_var, delta_var, op_proof_g_var};
    //transcript_type transcript;

    typename binding::fr_data<var, batch_size> fr_data = {scalars_var, {cip_var}};

    std::array<batch_proof_type, batch_size> prepared_proofs; // = {{{comm_var, o_var}}};

    typename component_type::params_type params; // = {prepared_proofs, {H_var, {PI_G_var}, {PI_G_var}}, fr_data};
    
    for (std::size_t i = 0; i < comm_len; i++){
        params.proofs[0].comm[i].parts[0] = comm_var[i];
    }
    params.proofs[0].opening_proof.G = op_proof_g_var;
    params.proofs[0].opening_proof.L = L_var;
    params.proofs[0].opening_proof.R = R_var;
    params.verifier_index.H = H_var;
    params.verifier_index.G = G_var;
    params.fr_output.scalars = scalars_var;
    params.proofs[0].opening_proof.delta = delta_var;
    params.fr_output.cip_shifted[0] = cip_var;
    params.proofs[0].transcript.sponge.state[0] = state0_var;
    params.proofs[0].transcript.sponge.state[1] =  state1_var;
    params.proofs[0].transcript.sponge.state[2] =  state2_var;


//    params.verifier_index.
    
    // prepared_proofs.

    // bases[bases_idx++] = params.proofs[i].opening_proof.L[j];
    // bases[bases_idx++] = params.proofs[i].opening_proof.R[j];

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {
        assert (assignment.var_value(real_res.output.X) == 0);
        assert (assignment.var_value(real_res.output.Y) == 0);
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
};
BOOST_AUTO_TEST_SUITE_END()