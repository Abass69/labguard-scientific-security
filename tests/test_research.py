import unittest
from labguard.research import generate,FEATURES,matrix,fit,aggregate
class ResearchTests(unittest.TestCase):
    def test_deterministic_and_disjoint(self):
        events,rows=generate();self.assertEqual(rows,generate()[1]);self.assertEqual(len(rows),720)
        self.assertEqual(len({(r['actor'],r['bucket']) for r in rows}),720)
        self.assertTrue(all(r['label']==0 for r in rows if r['split']!='test'))
        for a,b in [('train','calibration'),('calibration','test')]:
            self.assertLess(max(r['bucket'] for r in rows if r['split']==a),min(r['bucket'] for r in rows if r['split']==b))
        self.assertNotIn('label',FEATURES);self.assertNotIn('scenario',FEATURES);self.assertEqual(matrix(rows).shape,(720,6))
    def test_test_data_does_not_change_fit(self):
        _,rows=generate();model,threshold=fit(rows);changed=[dict(r) for r in rows]
        for r in changed:
            if r['split']=='test': r['requests']=999999
        model2,threshold2=fit(changed);self.assertEqual(threshold,threshold2)
        self.assertEqual(model.score_samples(matrix(rows)).tolist(),model2.score_samples(matrix(rows)).tolist())
    def test_feature_aggregation(self):
        rows=aggregate([dict(actor='a',ts=0,action='login',outcome='deny',records=0),dict(actor='a',ts=1,action='export',outcome='allow',records=5)])
        self.assertEqual([rows[0][f] for f in FEATURES],[2,1,1,1,5,1])
