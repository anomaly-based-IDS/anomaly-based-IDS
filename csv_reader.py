import logging
from typing import Generator, Optional
import numpy as np
import pandas as pd

from flow import FlowKey, FlowRecord, FEATURE_NAMES

logger = logging.getLogger(__name__)

_CSV_COL_MAP = {
    "Flow Duration": "duration",
    "Total Fwd Packets": "pkt_count",
    "Total Length of Fwd Packets": "byte_count",
    "Flow IAT Mean": "iat_mean",
    # 필요한 컬럼 추가
}

class CsvFlowReader:
    def __init__(self, label_col: str = "Label", chunksize: int = 1000):
        self.label_col = label_col
        self.chunksize = chunksize
    
    def read(self, csv_path: str) -> Generator[FlowRecord, None, None]:
        logger.info("=== CSV 파일 읽기 시작: %s ===", csv_path)
        total = 0

        for chunk in pd.read_csv(csv_path, chunksize = self.chunksize, encoding="utf-8", on_bad_lines="skip"):
            chunk.columns = chunk.columns.str.strip()

            for _, row in chunk.iterrows():
                record = self._row_to_record(row)
                if record is not None:
                    total += 1
                    yield record

        logger.info("=== CSV 파일 읽기 완료: %s | %d flow records ===", csv_path, total)

    def _row_to_record(self, row: pd.Series) -> Optional[FlowRecord]:
        try:
            feature_values = []
            for feat in FEATURE_NAMES:
                csv_col = next(
                    (c for c, f in _CSV_COL_MAP.items() if f == feat),
                    None
                )
                val = float(row.get(csv_col, 0.0)) if csv_col else 0.0
                feature_values.append(val if np.isfinite(val) else 0.0)
            
            features = np.array(feature_values, dtype=float)

            scr_ip = str(row.get("Source IP", row.get("Src IP", "0.0.0.0")))
            dst_ip = str(row.get("Destination IP", row.get("Dst IP", "0.0.0.0")))
            scr_port = int(row.get("Source Port", row.get("Src Port", 0)))
            dst_port = int(row.get("Destination Port", row.get("Dst Port", 0)))
            proto_num = str(row.get("Protocol", 6))
            protocol = {6: "TCP", 17: "UDP"}.get(proto_num, "OTHER")

            key = FlowKey(scr_ip, dst_ip, scr_port, dst_port, protocol)
            label = str(row.get(self.label_col, "")).strip()

            return FlowRecord(flow_key=key, features=features, label=label)
        
        except Exception as e:
            logger.debug("행 파싱 실패: %s ", e)
            return None