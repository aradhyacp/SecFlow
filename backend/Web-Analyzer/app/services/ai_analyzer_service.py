"""
AI Analyzer Service - Gemini-powered URL security analysis.
Ported from Url-Analyzer.
"""
import logging
import os

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """AI-powered analysis using Google Gemini API"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            logger.warning("GEMINI_API_KEY not set. AI analysis will not work.")
        self._client = None

    @property
    def client(self):
        if self._client is None and self.api_key:
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
            except ImportError:
                logger.error("google-genai package not installed.")
        return self._client

    def generate_report(self, analysis_result: dict) -> dict:
        """Generate AI summary from redirect chain analysis result"""
        try:
            if not self.client:
                return {
                    'status': 'error',
                    'error': 'Gemini API key not configured or google-genai not installed',
                    'ai_summary': None
                }

            analysis_summary = self._prepare_summary(analysis_result)
            prompt = self._build_prompt(analysis_summary)

            logger.info("Generating AI report using Gemini...")
            response = self.client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt,
            )

            return {
                'status': 'success',
                'ai_summary': response.text,
                'analysis_data': {
                    'original_url': analysis_result.get('original_url'),
                    'final_destination': analysis_result.get('final_destination'),
                    'total_hops': analysis_result.get('total_hops'),
                    'risk_level': analysis_result.get('risk_assessment', {}).get('level'),
                    'safety_score': analysis_result.get('risk_assessment', {}).get('score'),
                    'is_safe': analysis_result.get('is_safe')
                }
            }

        except Exception as e:
            logger.error(f"Error generating AI report: {str(e)}")
            return {'status': 'error', 'error': str(e), 'ai_summary': None}

    def _prepare_summary(self, analysis_result: dict) -> dict:
        redirect_chain = analysis_result.get('redirect_chain', [])
        risk_assessment = analysis_result.get('risk_assessment', {})
        return {
            'original_url': analysis_result.get('original_url'),
            'final_url': (analysis_result.get('final_destination') or {}).get('url'),
            'hops_count': analysis_result.get('total_hops'),
            'risk_level': risk_assessment.get('level'),
            'risk_score': risk_assessment.get('score'),
            'risk_reasons': risk_assessment.get('reasons', []),
            'is_safe': analysis_result.get('is_safe'),
            'redirect_details': [
                {
                    'hop': h.get('hop'),
                    'from': h.get('domain'),
                    'status': h.get('status_code'),
                    'types': h.get('types', [])
                }
                for h in redirect_chain[:10]
            ]
        }

    def _build_prompt(self, s: dict) -> str:
        prompt = f"""You are a cybersecurity expert analyzing URL redirect chains and web safety. Analyze the following URL security analysis and provide a comprehensive report.

ANALYSIS RESULTS:
- Original URL: {s['original_url']}
- Final Destination: {s['final_url']}
- Total Redirects/Hops: {s['hops_count']}
- Risk Level: {str(s['risk_level']).upper()}
- Safety Score: {s['risk_score']}/100
- Is Safe: {s['is_safe']}
- Risk Reasons: {', '.join(s['risk_reasons'])}

REDIRECT CHAIN DETAILS:"""
        for r in s['redirect_details']:
            prompt += f"\n  - Hop {r['hop']}: {r['from']} (Status: {r['status']}) - Types: {', '.join(r['types'])}"

        prompt += """

Based on this analysis, provide:
1. **Summary**: A brief overview of the URL analysis
2. **Risk Assessment**: What specific threats or concerns were identified
3. **Key Findings**: The most important observations about this URL
4. **Recommendations**: What actions the user should take
5. **Final Verdict**: Is this URL safe to visit? Why or why not?

Format your response in clear sections with markdown formatting. Be concise but thorough.
"""
        return prompt


# Module-level instance and public function
_ai_analyzer = AIAnalyzer()


def ai_analyze(url: str, redirect_chain_result: dict) -> dict:
    """
    Generate an AI-powered security report for a URL.
    Expects a pre-computed redirect_chain_result (from analyze_redirect_chain).
    """
    return _ai_analyzer.generate_report(redirect_chain_result)
