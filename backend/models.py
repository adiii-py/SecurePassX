"""
Pydantic Data Schemas for FastAPI Request/Response Validation
"""
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect for malicious & phishing indicators", example="https://login-micros0ft-security-portal.xyz/verify")
    enable_network_inspection: bool = Field(True, description="Whether to safely probe redirects, SSL, and HTML forms")


class EmailAnalysisRequest(BaseModel):
    raw_email: str = Field(..., description="Raw RFC 822 email text including headers and body")


class IOCModel(BaseModel):
    ioc_type: str
    raw_value: str
    defanged_value: str
    context: Optional[str] = ""


class IndicatorModel(BaseModel):
    key: str
    category: str
    weight: int
    description: str


class MITRETechniqueModel(BaseModel):
    id: str
    name: str
    tactic: str
    url: str
    description: str
    triggers: List[str]


class AnalysisReportModel(BaseModel):
    case_id: str
    timestamp: str
    analysis_type: str
    target_summary: str
    threat_score: int
    threat_verdict: str
    verdict_color: str
    mitre_mapping: List[MITRETechniqueModel]
    score_breakdown: List[IndicatorModel]
    playbook_actions: List[Dict[str, str]]
    iocs: List[IOCModel]
    details: Dict[str, Any]
