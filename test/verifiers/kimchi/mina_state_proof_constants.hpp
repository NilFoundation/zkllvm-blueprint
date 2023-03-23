struct mina_state_proof_constants{
    std::size_t witness_columns;
    std::size_t public_input_size;

    std::size_t max_poly_size;
    std::size_t eval_rounds; // = lr length = log2(g length)

    std::size_t perm_size;

    std::size_t srs_len; // g length
    std::size_t prev_chal_size;

    std::size_t batch_size;
};

//                                                                     w_col, pub_inp, max_poly, eval_r, perm_s, srs_l, prev_chal
constexpr static const mina_state_proof_constants generic_constants =   {15, 5, 32,   5,  7, 32,   0, 1};
constexpr static const mina_state_proof_constants recursion_constants = {15, 0, 32,   5,  7, 32,   1, 1};
constexpr static const mina_state_proof_constants ec_constants =        {15, 0, 512,  9,  7, 512,  0, 1};
constexpr static const mina_state_proof_constants chacha_constants =    {15, 0, 8192, 13, 7, 8192, 0, 1};