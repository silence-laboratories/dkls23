// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::path::PathBuf;

xflags::xflags! {
    cmd dkls-metrics {
        /// Run DKG and report execution time.
        cmd dkg {
            /// Number of participants
            required --n n: u8

            /// Threshold
            required --t t: u8

            /// Assign a rank to the next participant. If the number
            /// of given ranks is less than N, assign zero.
            repeated --rank ranks: u8

            /// Execute DKG K times in a row. Default 100.
            optional --k k: usize

            optional --dsg

            optional --pre-sign

            optional --key-refresh

            /// Path name of an instance file generated by subcommand trace-dkg.
            /// If this option is given then options `--n`, `--t` and `--rank`
            /// will be ignored.
            optional --trace trace: PathBuf
        }

        /// Run DKG with given parameters and save full trace of the
        /// execution into given directory.
        ///
        cmd trace-dkg {
            /// Assign a rank to the next participant. If the number
            /// of given ranks is less than N, assign zero.
            repeated --rank ranks: u8

            /// Number of participants
            required --n n: u8

            /// Threshold
            required --t t: u8

            /// Base directory to save messages, key shares, and instance-id.
            /// The command will create following files:
            /// - <key-id>.instance
            /// - <key-id>.messages
            /// - <msg-id>.msg
            /// - ...
            /// - <key-id>.share.00: first key share
            /// - ...
            ///
            /// Message IDs and key ID indirectly depends on instance-id
            /// generated by the command.
            required --trace trace: PathBuf
        }

        // cmd dsg {
        //     /// Number of participants
        //     required --n n: u8

        //     /// Threshold
        //     required --t t: u8

        // }

        // cmd trace-dsg {
        // }
    }
}
