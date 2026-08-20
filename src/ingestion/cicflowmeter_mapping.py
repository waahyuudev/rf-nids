"""Explicit, source-audited hieulw/cicflowmeter 0.4.2 feature aliases."""

from __future__ import annotations

# Each entry was checked against Flow.get_data() in hieulw/cicflowmeter 0.4.2.
# These are spelling/abbreviation changes only; fuzzy matching is never used.
EXTRACTOR_TO_MODEL_FEATURE = {
    "dst_port": "destination_port",
    "flow_byts_s": "flow_bytes_s",
    "flow_pkts_s": "flow_packets_s",
    "fwd_pkts_s": "fwd_packets_s",
    "bwd_pkts_s": "bwd_packets_s",
    "tot_fwd_pkts": "total_fwd_packets",
    "tot_bwd_pkts": "total_backward_packets",
    "totlen_fwd_pkts": "total_length_of_fwd_packets",
    "totlen_bwd_pkts": "total_length_of_bwd_packets",
    "fwd_pkt_len_max": "fwd_packet_length_max",
    "fwd_pkt_len_min": "fwd_packet_length_min",
    "fwd_pkt_len_mean": "fwd_packet_length_mean",
    "fwd_pkt_len_std": "fwd_packet_length_std",
    "bwd_pkt_len_max": "bwd_packet_length_max",
    "bwd_pkt_len_min": "bwd_packet_length_min",
    "bwd_pkt_len_mean": "bwd_packet_length_mean",
    "bwd_pkt_len_std": "bwd_packet_length_std",
    "pkt_len_max": "max_packet_length",
    "pkt_len_min": "min_packet_length",
    "pkt_len_mean": "packet_length_mean",
    "pkt_len_std": "packet_length_std",
    "pkt_len_var": "packet_length_variance",
    "fwd_header_len": "fwd_header_length",
    "bwd_header_len": "bwd_header_length",
    "fwd_seg_size_min": "min_seg_size_forward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_iat_tot": "fwd_iat_total",
    "bwd_iat_tot": "bwd_iat_total",
    "fin_flag_cnt": "fin_flag_count",
    "syn_flag_cnt": "syn_flag_count",
    "rst_flag_cnt": "rst_flag_count",
    "psh_flag_cnt": "psh_flag_count",
    "ack_flag_cnt": "ack_flag_count",
    "urg_flag_cnt": "urg_flag_count",
    "ece_flag_cnt": "ece_flag_count",
    "pkt_size_avg": "average_packet_size",
    "init_fwd_win_byts": "init_win_bytes_forward",
    "init_bwd_win_byts": "init_win_bytes_backward",
    "fwd_byts_b_avg": "fwd_avg_bytes_bulk",
    "fwd_pkts_b_avg": "fwd_avg_packets_bulk",
    "fwd_blk_rate_avg": "fwd_avg_bulk_rate",
    "bwd_byts_b_avg": "bwd_avg_bytes_bulk",
    "bwd_pkts_b_avg": "bwd_avg_packets_bulk",
    "bwd_blk_rate_avg": "bwd_avg_bulk_rate",
    "fwd_seg_size_avg": "avg_fwd_segment_size",
    "bwd_seg_size_avg": "avg_bwd_segment_size",
    "subflow_fwd_pkts": "subflow_fwd_packets",
    "subflow_fwd_byts": "subflow_fwd_bytes",
    "subflow_bwd_pkts": "subflow_bwd_packets",
    "subflow_bwd_byts": "subflow_bwd_bytes",
}

ALIAS_EVIDENCE = {
    extractor: (
        "Verified against hieulw/cicflowmeter 0.4.2 Flow.get_data(): the extractor "
        "field and model field represent the same named calculation."
    )
    for extractor in EXTRACTOR_TO_MODEL_FEATURE
}

INCOMPATIBLE_MODEL_FEATURES = {
    "fwd_header_length.1": {
        "extractor_candidate": None,
        "reason": (
            "No second independent forward-header-length field exists. fwd_header_len "
            "is already consumed by fwd_header_length and must not be copied."
        ),
    },
    "cwe_flag_count": {
        "extractor_candidate": "cwr_flag_count",
        "reason": (
            "Not equivalent in this build: Flow.get_data() assigns cwr_flag_count from "
            "fwd_urg_flags instead of counting the TCP CWR flag."
        ),
    },
}
