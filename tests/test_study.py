import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "study"))
import features  # noqa: E402
import run_study  # noqa: E402

SRC_A = '''
public class BenchmarkTest00001 extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getParameter("BenchmarkTest00001");

        String bar;
        int num = 106;
        bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;

        String sql = "SELECT * FROM USERS WHERE ID='" + bar + "'"; // sink
    }
}
'''

# Same dataflow template, different test name and constants.
SRC_B = SRC_A.replace("00001", "00777").replace("106", "86").replace("18", "42")


def test_template_id_ignores_names_and_constants():
    assert features.template_id(SRC_A) == features.template_id(SRC_B)


def test_template_id_changes_with_dataflow_shape():
    other = SRC_A.replace('bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;',
                          "bar = param;")
    assert features.template_id(other) != features.template_id(SRC_A)


def test_propagator_block_uses_helper_method_when_present():
    src = '''
    public void doPost(HttpServletRequest request) {
        String param = request.getParameter("x");
        String bar = new Test().doSomething(request, param);
    }
    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar = param.split(" ")[0];
            return bar;
        }
    }
    '''
    block = features.propagator_block(src)
    assert any("split" in line for line in block)
    assert not any("getParameter" in line for line in block)


def test_masking_removes_string_and_number_tells():
    masked = run_study.code_text(SRC_A, mask_strings=True, mask_numbers=True)
    assert "This_should_always_happen" not in masked
    assert "106" not in masked and "200" not in masked
    assert "STR" in masked and "NUM" in masked
    # comments and the test name are stripped in every view
    raw = run_study.code_text(SRC_A)
    assert "sink" not in raw and "BenchmarkTest" not in raw


def test_masking_handles_escaped_quotes():
    src = 'public void doPost() { String s = "a \\"quoted\\" word"; }'
    assert "quoted" not in run_study.code_text(src, mask_strings=True)


def test_ece_perfect_and_worst_case():
    y = np.array([0, 0, 1, 1])
    assert run_study.ece(y, np.array([0.0, 0.0, 1.0, 1.0])) == 0.0
    assert abs(run_study.ece(y, np.array([1.0, 1.0, 0.0, 0.0])) - 1.0) < 1e-9


def test_threshold_for_recall_hits_target():
    rng = np.random.default_rng(0)
    y = np.r_[np.ones(200, int), np.zeros(200, int)]
    p = np.r_[rng.uniform(0.3, 1, 200), rng.uniform(0, 0.7, 200)]
    thr = run_study.threshold_for_recall(y, p, 0.95)
    assert (p[y == 1] >= thr).mean() >= 0.95
