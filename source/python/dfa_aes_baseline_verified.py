
"""
dfa_aes_baseline.py

AES-128 + software fault injection + classical DFA baseline.

This is the FIRST implementation for the research project:
"Differential Fault Analysis under Multiple and Imperfect Fault Models"

Current scope:
    1. AES-128
    2. single-byte transient XOR fault
    3. fault injected in round 9, AFTER ShiftRows and BEFORE MixColumns
    4. known fault column/location
    5. random or chosen nonzero fault value
    6. recover round-10 key bytes using DFA equations
    7. invert AES-128 key schedule to recover the master key

The code is deliberately dependency-free so it is easy to debug.

State convention:
    AES state is stored column-major:
        index = 4 * column + row

So:
    state[0]  = row 0, column 0
    state[1]  = row 1, column 0
    ...
    state[15] = row 3, column 3
"""

from __future__ import annotations

import itertools
import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple


# ============================================================================
# AES CONSTANTS
# ============================================================================

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

INV_SBOX = [0] * 256
for i, value in enumerate(SBOX):
    INV_SBOX[value] = i

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# ============================================================================
# SMALL UTILITIES
# ============================================================================

def xor_bytes(a: Sequence[int], b: Sequence[int]) -> List[int]:
    return [x ^ y for x, y in zip(a, b)]


def bytes_to_hex(data: Sequence[int]) -> str:
    return bytes(data).hex().upper()


def hex_to_bytes(text: str) -> List[int]:
    text = text.replace(" ", "").replace(":", "")
    if len(text) % 2:
        raise ValueError("Hex string must contain an even number of digits.")
    return list(bytes.fromhex(text))


def hamming_weight(x: int) -> int:
    return x.bit_count()


def hamming_weight_bytes(data: Sequence[int]) -> int:
    return sum(hamming_weight(x) for x in data)


def xtime(a: int) -> int:
    """GF(2^8): multiply by x / 0x02."""
    return ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF


def gf_mul(a: int, b: int) -> int:
    """General multiplication in AES's GF(2^8)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


# ============================================================================
# AES ROUND FUNCTIONS
# ============================================================================

def sub_bytes(state: Sequence[int]) -> List[int]:
    return [SBOX[x] for x in state]


def shift_rows(state: Sequence[int]) -> List[int]:
    """
    AES ShiftRows.

    With column-major storage:
        output[row, col] = input[row, (col + row) mod 4]
    """
    out = [0] * 16

    for row in range(4):
        for col in range(4):
            out[4 * col + row] = state[4 * ((col + row) % 4) + row]

    return out


def mix_columns(state: Sequence[int]) -> List[int]:
    """AES MixColumns."""
    out = [0] * 16

    for col in range(4):
        a0, a1, a2, a3 = state[4*col:4*col+4]

        out[4*col + 0] = (
            xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
        )
        out[4*col + 1] = (
            a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
        )
        out[4*col + 2] = (
            a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
        )
        out[4*col + 3] = (
            (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)
        )

    return out


def add_round_key(state: Sequence[int], round_key: Sequence[int]) -> List[int]:
    return xor_bytes(state, round_key)


# ============================================================================
# AES-128 KEY EXPANSION
# ============================================================================

def rot_word(word: Sequence[int]) -> List[int]:
    return list(word[1:]) + list(word[:1])


def sub_word(word: Sequence[int]) -> List[int]:
    return [SBOX[x] for x in word]


def expand_key(key: Sequence[int]) -> List[List[int]]:
    """
    Expand a 16-byte AES-128 key into 11 round keys.
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must contain exactly 16 bytes.")

    words: List[List[int]] = [
        list(key[4*i:4*i+4]) for i in range(4)
    ]

    for i in range(4, 44):
        temp = words[i - 1].copy()

        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // 4]

        words.append(xor_bytes(words[i - 4], temp))

    return [sum(words[4*r:4*r+4], []) for r in range(11)]


def invert_last_round_key(last_round_key: Sequence[int]) -> List[int]:
    """
    Reverse the AES-128 key schedule.

    Input:
        round-10 key

    Output:
        original round-0/master key
    """
    if len(last_round_key) != 16:
        raise ValueError("Round key must contain exactly 16 bytes.")

    current = [
        list(last_round_key[4*i:4*i+4])
        for i in range(4)
    ]

    for round_number in range(10, 0, -1):
        prev = [None, None, None, None]

        # w[4r+3] = w[4r-1] XOR w[4r+2]
        prev[3] = xor_bytes(current[3], current[2])

        # w[4r+2] = w[4r-2] XOR w[4r+1]
        prev[2] = xor_bytes(current[2], current[1])

        # w[4r+1] = w[4r-3] XOR w[4r]
        prev[1] = xor_bytes(current[1], current[0])

        # w[4r] = w[4r-4] XOR g(w[4r-1])
        temp = sub_word(rot_word(prev[3]))
        temp[0] ^= RCON[round_number]
        prev[0] = xor_bytes(current[0], temp)

        current = prev  # type: ignore

    return sum(current, [])


# ============================================================================
# FAULT MODEL
# ============================================================================

@dataclass(frozen=True)
class Fault:
    """
    A software XOR fault.

    round:
        AES round in which the fault is inserted (1..9 here).

    state_index:
        Location in the AES state immediately AFTER ShiftRows and
        immediately BEFORE MixColumns.

    value:
        XOR mask. Must be 1..255.
    """
    round: int
    state_index: int
    value: int


# ============================================================================
# AES ENCRYPTION WITH OPTIONAL FAULT
# ============================================================================

def aes_encrypt(
    plaintext: Sequence[int],
    key: Sequence[int],
    fault: Optional[Fault] = None,
    trace: bool = False,
) -> Tuple[List[int], Optional[Dict[str, List[int]]]]:
    """
    AES-128 encryption.

    If fault is supplied, inject it AFTER ShiftRows and BEFORE MixColumns
    in the selected round.

    Returning a trace is useful for debugging and for understanding fault
    propagation.
    """
    if len(plaintext) != 16:
        raise ValueError("Plaintext must contain exactly 16 bytes.")
    if len(key) != 16:
        raise ValueError("AES-128 key must contain exactly 16 bytes.")

    if fault is not None:
        if not (1 <= fault.round <= 9):
            raise ValueError("Fault round must be 1..9.")
        if not (0 <= fault.state_index < 16):
            raise ValueError("Fault state index must be 0..15.")
        if not (1 <= fault.value <= 255):
            raise ValueError("Fault value must be 1..255.")

    round_keys = expand_key(key)

    state = add_round_key(list(plaintext), round_keys[0])

    states: Dict[str, List[int]] = {}

    if trace:
        states["round0_addkey"] = state.copy()

    for rnd in range(1, 11):
        state = sub_bytes(state)

        if trace:
            states[f"round{rnd}_subbytes"] = state.copy()

        state = shift_rows(state)

        if trace:
            states[f"round{rnd}_shiftrows"] = state.copy()

        if rnd != 10:
            # --------------------------------------------------------------
            # THIS is the baseline DFA fault point:
            #
            #       SubBytes -> ShiftRows -> [FAULT] -> MixColumns
            #
            # A single-byte difference becomes a four-byte difference
            # through MixColumns.
            # --------------------------------------------------------------
            if fault is not None and rnd == fault.round:
                state[fault.state_index] ^= fault.value

                if trace:
                    states[f"round{rnd}_faulted"] = state.copy()

            state = mix_columns(state)

            if trace:
                states[f"round{rnd}_mixcolumns"] = state.copy()

        state = add_round_key(state, round_keys[rnd])

        if trace:
            states[f"round{rnd}_addkey"] = state.copy()

    return state, (states if trace else None)


# ============================================================================
# DFA GEOMETRY
# ============================================================================

def affected_ciphertext_indices(fault_column: int) -> List[int]:
    """
    Map one affected MixColumns column to the four ciphertext positions.

    The returned positions are in row order.

    After MixColumns, differences are in one column:
        row 0 -> 02*epsilon
        row 1 -> epsilon
        row 2 -> epsilon
        row 3 -> 03*epsilon

    Round 10 has ShiftRows, so row r moves to:
        output_column = (fault_column - r) mod 4
    """
    if not (0 <= fault_column < 4):
        raise ValueError("fault_column must be 0..3.")

    positions = []

    for row in range(4):
        output_col = (fault_column - row) % 4
        positions.append(4 * output_col + row)

    return positions


def expected_output_difference(row: int, epsilon: int) -> int:
    """
    Difference entering the final-round SubBytes, after MixColumns.
    """
    if not (1 <= epsilon <= 255):
        raise ValueError("epsilon must be 1..255.")

    if row == 0:
        return gf_mul(0x02, epsilon)
    if row in (1, 2):
        return epsilon
    if row == 3:
        return gf_mul(0x03, epsilon)

    raise ValueError("row must be 0..3.")


def print_fault_propagation(
    correct: Sequence[int],
    faulty: Sequence[int],
    fault_column: int,
) -> None:
    """
    Human-readable view of C XOR C'.
    """
    delta = xor_bytes(correct, faulty)
    positions = affected_ciphertext_indices(fault_column)

    print("Correct ciphertext :", bytes_to_hex(correct))
    print("Faulty ciphertext  :", bytes_to_hex(faulty))
    print("Ciphertext delta   :", bytes_to_hex(delta))
    print("Changed positions  :", [i for i, x in enumerate(delta) if x])
    print("Expected positions :", positions)
    print("HW(delta)          :", hamming_weight_bytes(delta))


# ============================================================================
# DFA CANDIDATE TESTING
# ============================================================================

def byte_key_candidates(
    correct_ciphertext_byte: int,
    faulty_ciphertext_byte: int,
    expected_difference: int,
) -> List[int]:
    """
    Test all 256 possible values for ONE byte of the AES round-10 key.

    Final AES round:
        C  = S(X)  XOR K
        C' = S(X') XOR K

    Therefore:
        X  = InvS(C  XOR K)
        X' = InvS(C' XOR K)

    and DFA tests:
        X XOR X' = expected_difference
    """
    candidates = []

    for key_byte in range(256):
        x = INV_SBOX[correct_ciphertext_byte ^ key_byte]
        x_faulty = INV_SBOX[faulty_ciphertext_byte ^ key_byte]

        if (x ^ x_faulty) == expected_difference:
            candidates.append(key_byte)

    return candidates


def four_byte_candidates_for_pair(
    correct_ciphertext: Sequence[int],
    faulty_ciphertext: Sequence[int],
    fault_column: int,
) -> List[Tuple[int, int, int, int]]:
    """
    Generate all 4-byte round-10-key candidates for one faulty pair.

    epsilon is unknown, so try epsilon = 1..255.

    IMPORTANT:
        The SAME epsilon must explain all four bytes of the affected
        MixColumns column.
    """
    positions = affected_ciphertext_indices(fault_column)
    candidates = set()

    for epsilon in range(1, 256):
        candidate_lists = []

        for row, pos in enumerate(positions):
            expected = expected_output_difference(row, epsilon)

            byte_candidates = byte_key_candidates(
                correct_ciphertext[pos],
                faulty_ciphertext[pos],
                expected,
            )

            if not byte_candidates:
                break

            candidate_lists.append(byte_candidates)

        if len(candidate_lists) == 4:
            for candidate_tuple in itertools.product(*candidate_lists):
                candidates.add(tuple(candidate_tuple))

    return sorted(candidates)


def recover_round_key_column(
    faulty_pairs: Sequence[Tuple[Sequence[int], Sequence[int]]],
    fault_column: int,
) -> List[Tuple[int, int, int, int]]:
    """
    Recover a 4-byte round-10-key group.

    Multiple faulty pairs are useful because each pair produces a candidate
    set. We intersect those candidate sets.
    """
    if not faulty_pairs:
        raise ValueError("Provide at least one faulty ciphertext pair.")

    current = set(
        four_byte_candidates_for_pair(
            faulty_pairs[0][0],
            faulty_pairs[0][1],
            fault_column,
        )
    )

    for correct, faulty in faulty_pairs[1:]:
        next_set = set(
            four_byte_candidates_for_pair(
                correct,
                faulty,
                fault_column,
            )
        )

        current &= next_set

        # If only one remains, no reason to process more pairs.
        if len(current) <= 1:
            break

    return sorted(current)


def assemble_round10_key(
    recovered_columns: Dict[int, Tuple[int, int, int, int]]
) -> List[int]:
    """
    Put the recovered 4-byte groups into the 16-byte round-10 key.

    The candidate tuple is stored in row order, while the corresponding
    ciphertext positions are after ShiftRows.
    """
    round10_key: List[Optional[int]] = [None] * 16

    for fault_column, group in recovered_columns.items():
        positions = affected_ciphertext_indices(fault_column)

        for value, position in zip(group, positions):
            round10_key[position] = value

    if any(value is None for value in round10_key):
        raise ValueError("All four fault columns are required.")

    return [int(value) for value in round10_key]


# ============================================================================
# EXPERIMENT GENERATION
# ============================================================================

def generate_faulty_pair(
    key: Sequence[int],
    plaintext: Sequence[int],
    fault_column: int,
    fault_value: Optional[int] = None,
) -> Tuple[List[int], List[int], Fault]:
    """
    Generate one correct/faulty pair.

    We use row 0 of the selected column as the injected byte.

    fault_value=None -> choose a random nonzero byte.
    """
    if not (0 <= fault_column < 4):
        raise ValueError("fault_column must be 0..3.")

    if fault_value is None:
        fault_value = random.randint(1, 255)

    if not (1 <= fault_value <= 255):
        raise ValueError("fault_value must be 1..255.")

    state_index = 4 * fault_column  # row 0 of the selected column

    fault = Fault(
        round=9,
        state_index=state_index,
        value=fault_value,
    )

    correct, _ = aes_encrypt(plaintext, key)
    faulty, _ = aes_encrypt(plaintext, key, fault=fault)

    return correct, faulty, fault


def generate_dataset(
    key: Sequence[int],
    pairs_per_column: int = 4,
    seed: int = 12345,
) -> Dict[int, List[Tuple[List[int], List[int], Fault]]]:
    """
    Generate an idealized baseline DFA dataset for all four columns.
    """
    rng = random.Random(seed)

    dataset: Dict[int, List[Tuple[List[int], List[int], Fault]]] = {}

    for column in range(4):
        dataset[column] = []

        for _ in range(pairs_per_column):
            plaintext = [rng.randrange(256) for _ in range(16)]
            fault_value = rng.randrange(1, 256)

            # We use our own RNG above so the demo is reproducible.
            fault = Fault(
                round=9,
                state_index=4 * column,
                value=fault_value,
            )

            correct, _ = aes_encrypt(plaintext, key)
            faulty, _ = aes_encrypt(plaintext, key, fault=fault)

            dataset[column].append((correct, faulty, fault))

    return dataset


# ============================================================================
# TESTS
# ============================================================================

def self_test() -> None:
    """
    Run tests BEFORE touching the DFA experiment.
    If one of these fails, do not debug DFA yet.
    """
    key = hex_to_bytes("000102030405060708090A0B0C0D0E0F")
    plaintext = hex_to_bytes("00112233445566778899AABBCCDDEEFF")

    # FIPS-197 AES-128 known-answer test.
    expected = "69C4E0D86A7B0430D8CDB78070B4C55A"

    ciphertext, _ = aes_encrypt(plaintext, key)

    assert bytes_to_hex(ciphertext) == expected, (
        "AES-128 test vector failed.\n"
        f"Expected: {expected}\n"
        f"Got     : {bytes_to_hex(ciphertext)}"
    )

    # Key schedule inversion.
    round_keys = expand_key(key)
    recovered_master = invert_last_round_key(round_keys[10])

    assert recovered_master == key, (
        "AES key-schedule inversion failed."
    )

    # Fault propagation is checked at the INTERNAL state where the fault
    # model says it should be checked, not directly on C XOR C'.
    #
    # C XOR C' is NOT expected to equal [02e,e,e,03e] because the final
    # round contains a nonlinear S-box.
    fault = Fault(round=9, state_index=0, value=0x53)

    normal, _ = aes_encrypt(plaintext, key, trace=False)
    faulty, trace = aes_encrypt(plaintext, key, fault=fault, trace=True)

    assert trace is not None

    correct_internal = trace["round9_mixcolumns"]

    # Run a normal encryption trace to get the matching normal state.
    _, normal_trace = aes_encrypt(plaintext, key, trace=True)
    assert normal_trace is not None
    normal_internal = normal_trace["round9_mixcolumns"]

    delta_internal = xor_bytes(normal_internal, correct_internal)

    expected_internal = [0] * 16
    expected_internal[0] = gf_mul(0x02, 0x53)
    expected_internal[1] = 0x53
    expected_internal[2] = 0x53
    expected_internal[3] = gf_mul(0x03, 0x53)

    assert delta_internal == expected_internal, (
        "Round-9 fault propagation test failed.\n"
        f"Expected: {bytes_to_hex(expected_internal)}\n"
        f"Got     : {bytes_to_hex(delta_internal)}"
    )

    # Exhaustive geometry check for every possible single-byte location.
    # The fault is injected after ShiftRows and before MixColumns in round 9.
    # For a fault in input row r, MixColumns produces the r-th column of M
    # multiplied by epsilon. The resulting four state bytes are then moved
    # by round-10 ShiftRows to four distinct ciphertext positions.
    mix_columns_matrix = (
        (0x02, 0x03, 0x01, 0x01),
        (0x01, 0x02, 0x03, 0x01),
        (0x01, 0x01, 0x02, 0x03),
        (0x03, 0x01, 0x01, 0x02),
    )

    for fault_column in range(4):
        for fault_row in range(4):
            epsilon = 0x53
            state_index = 4 * fault_column + fault_row
            test_fault = Fault(9, state_index, epsilon)

            correct_ct, correct_trace = aes_encrypt(plaintext, key, trace=True)
            faulty_ct, faulty_trace = aes_encrypt(plaintext, key, fault=test_fault, trace=True)
            assert correct_trace is not None and faulty_trace is not None

            # Check the exact differential immediately after round-9 MixColumns.
            actual_internal_delta = xor_bytes(
                correct_trace["round9_mixcolumns"],
                faulty_trace["round9_mixcolumns"],
            )
            expected_internal_delta = [0] * 16
            for output_row in range(4):
                coeff = mix_columns_matrix[output_row][fault_row]
                expected_internal_delta[4 * fault_column + output_row] = gf_mul(coeff, epsilon)

            assert actual_internal_delta == expected_internal_delta, (
                f"Internal propagation failed for row={fault_row}, column={fault_column}. "
                f"Expected {bytes_to_hex(expected_internal_delta)}, "
                f"got {bytes_to_hex(actual_internal_delta)}"
            )

            # Check the four nonzero ciphertext-difference positions after
            # final-round ShiftRows and SubBytes.
            expected_positions = sorted(
                4 * ((fault_column - row) % 4) + row
                for row in range(4)
            )
            actual_positions = [
                i for i, (a, b) in enumerate(zip(correct_ct, faulty_ct))
                if a != b
            ]
            assert actual_positions == expected_positions, (
                f"Ciphertext geometry failed for row={fault_row}, column={fault_column}. "
                f"Expected {expected_positions}, got {actual_positions}"
            )

    print("[PASS] AES-128 FIPS-197 known-answer test")
    print("[PASS] AES-128 key-schedule inversion test")
    print("[PASS] Round-9 single-byte propagation for all 16 state locations")
    print("[PASS] Final-round ShiftRows ciphertext geometry for all 16 locations")


# ============================================================================
# END-TO-END BASELINE DEMO
# ============================================================================

def run_baseline_demo() -> None:
    print("\n" + "=" * 72)
    print("AES-128 DIFFERENTIAL FAULT ANALYSIS — BASELINE")
    print("=" * 72)

    secret_key = hex_to_bytes(
        "000102030405060708090A0B0C0D0E0F"
    )

    print("Secret master key:", bytes_to_hex(secret_key))

    dataset = generate_dataset(
        secret_key,
        pairs_per_column=4,
        seed=12345,
    )

    recovered_columns: Dict[int, Tuple[int, int, int, int]] = {}

    for column in range(4):
        print("\n" + "-" * 72)
        print(f"FAULT COLUMN {column}")
        print("-" * 72)

        pairs = [
            (correct, faulty)
            for correct, faulty, _fault in dataset[column]
        ]

        for number, (correct, faulty) in enumerate(pairs, start=1):
            delta = xor_bytes(correct, faulty)
            changed = [i for i, x in enumerate(delta) if x]

            print(
                f"Pair {number}: "
                f"changed ciphertext bytes={changed}, "
                f"HW(C XOR C')={hamming_weight_bytes(delta)}"
            )

        candidates = recover_round_key_column(
            pairs,
            column,
        )

        print(
            "Surviving 4-byte round-key candidates:",
            len(candidates),
        )

        if len(candidates) == 1:
            recovered_columns[column] = candidates[0]
            print(
                "Recovered group:",
                bytes_to_hex(candidates[0])
            )
        else:
            print("WARNING: more than one candidate remains.")
            for candidate in candidates[:10]:
                print("   ", bytes_to_hex(candidate))

    if len(recovered_columns) == 4:
        recovered_round10_key = assemble_round10_key(
            recovered_columns
        )

        recovered_master_key = invert_last_round_key(
            recovered_round10_key
        )

        print("\n" + "=" * 72)
        print("FINAL RESULT")
        print("=" * 72)
        print(
            "Recovered round-10 key:",
            bytes_to_hex(recovered_round10_key)
        )
        print(
            "Recovered master key  :",
            bytes_to_hex(recovered_master_key)
        )

        if recovered_master_key == secret_key:
            print("\n[SUCCESS] Full AES-128 master key recovered.")
        else:
            print("\n[FAIL] Recovered key does not match.")
    else:
        print(
            "\n[INCOMPLETE] Not all four key groups were uniquely recovered."
        )


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    self_test()
    run_baseline_demo()
