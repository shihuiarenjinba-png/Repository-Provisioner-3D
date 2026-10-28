import unittest
from registration_router import registration_type, user_id_request, STANDARD, GDK

JOB = dict(product_type="GAME_3D", request_id="3d-prism-route-3d-abcdef012345",
           source_sha="a"*40, source_branch="codex/3d-canary-prism-route-20261028",
           slug="prism-route-3d", display_name="Prism Route 3D")
EVIDENCE = dict(status="PRE_IDENTITY_BYTES_CORRELATED",
                evidence_scope="FACTORY_ARTIFACT_BYTES_NOT_STORE_E2E",
                request_id=JOB["request_id"], source_sha=JOB["source_sha"],
                slug=JOB["slug"], factory_build_head="b"*40,
                workflow_run_id=123, artifact_id=456,
                payload_authority="AUTHENTICATED_FACTORY_ARTIFACT",
                artifact_sha256="c"*64, exe_sha256="d"*64,
                external_pck_sha256="e"*64,
                post_identity_ready=False,
                windows_install_gpu_gui_verified=False)

class RegistrationRouterTests(unittest.TestCase):
    def test_makeappx_is_msix_game_not_exe_app(self):
        result=registration_type(STANDARD,builder="Windows SDK MakeAppx",
                                 output_kind="msix",gdk_config=False)
        self.assertEqual(result["registration_type"],"MSIX_OR_PWA_GAME")
        self.assertEqual(result["partner_center_selection"],"MSIX or PWA game")
    def test_gdk_requires_actual_gdk(self):
        self.assertEqual(registration_type(GDK,builder="Microsoft GDK",
                         output_kind="msixvc",gdk_config=True)["registration_type"],"GDK_GAME")
        self.assertEqual(registration_type(GDK,builder="Windows SDK MakeAppx",
                         output_kind="msix",gdk_config=False)["status"],"HOLD_REGISTRATION_TYPE_UNRESOLVED")
    def test_exe_intermediate_is_not_exe_or_msi(self):
        self.assertEqual(registration_type(STANDARD,builder="Godot",
                         output_kind="exe",gdk_config=False)["status"],"HOLD_REGISTRATION_TYPE_UNRESOLVED")
    def test_user_id_request_after_verified_factory_provenance(self):
        result=user_id_request(JOB,EVIDENCE,strategy=STANDARD,
                     builder="Windows SDK MakeAppx",output_kind="msix",gdk_config=False)
        self.assertEqual(result["status"],"USER_ID_REQUEST")
        self.assertEqual(result["product_name"],"Prism Route 3D")
        self.assertEqual(len(result["required_partner_center_fields"]),7)
        self.assertNotIn("Xbox Title ID",result["required_partner_center_fields"])
        self.assertIsNone(result["identity_values"])
        self.assertFalse(result["post_identity_ready"])
        self.assertEqual(result["factory_artifact_id"], 456)
        self.assertEqual(result["factory_artifact_sha256"], "c"*64)
        self.assertEqual(result["exe_sha256"], "d"*64)
        self.assertEqual(result["external_pck_sha256"], "e"*64)
        self.assertEqual(result["source_branch"], JOB["source_branch"])
        self.assertEqual(result["identity_return_target"],
                         "products/prism-route-3d/store/approved-identity.json")
    def test_no_request_without_real_verified_provenance(self):
        for key,value in (("status","HOLD"),("evidence_scope","OFFLINE_FIXTURE"),
                          ("request_id","other-request"),("source_sha","f"*40),
                          ("slug","other-product"),("factory_build_head","invalid"),
                          ("artifact_id",None),("payload_authority","LOCAL_FIXTURE"),
                          ("artifact_sha256","invalid"),("exe_sha256",None),
                          ("external_pck_sha256","f"*63),
                          ("post_identity_ready",True),
                          ("windows_install_gpu_gui_verified",True),
                          ("workflow_run_id",True)):
            with self.subTest(key=key):
                e=dict(EVIDENCE,**{key:value})
                result=user_id_request(JOB,e,strategy=STANDARD,
                         builder="Windows SDK MakeAppx",output_kind="msix",gdk_config=False)
                self.assertEqual(result["status"],"HOLD_PRE_IDENTITY_NOT_READY")
                self.assertEqual(result["user_id_request"],"まだ不要")
    def test_missing_provenance_fields_fail_closed(self):
        for key in ("payload_authority", "artifact_sha256", "exe_sha256",
                    "post_identity_ready", "windows_install_gpu_gui_verified"):
            with self.subTest(key=key):
                e = dict(EVIDENCE)
                e.pop(key)
                result = user_id_request(JOB, e, strategy=STANDARD,
                    builder="Windows SDK MakeAppx", output_kind="msix", gdk_config=False)
                self.assertEqual(result["status"], "HOLD_PRE_IDENTITY_NOT_READY")

    def test_malformed_branch_or_packaging_kind_fails_closed(self):
        for branch in ("codex/../main", "codex//evil", "main"):
            with self.subTest(branch=branch):
                result = user_id_request(dict(JOB, source_branch=branch), EVIDENCE,
                    strategy=STANDARD, builder="Windows SDK MakeAppx",
                    output_kind="msix", gdk_config=False)
                self.assertEqual(result["status"], "HOLD_PRE_IDENTITY_NOT_READY")
        self.assertEqual(registration_type(STANDARD, builder="Windows SDK MakeAppx",
            output_kind=None, gdk_config=False)["status"],
            "HOLD_REGISTRATION_TYPE_UNRESOLVED")

    def test_gdk_request_adds_xbox_fields_only_with_gdk_evidence(self):
        result=user_id_request(JOB,EVIDENCE,strategy=GDK,
                     builder="Microsoft GDK",output_kind="msixvc",gdk_config=True)
        self.assertEqual(result["status"],"USER_ID_REQUEST")
        self.assertEqual(len(result["required_partner_center_fields"]),10)

if __name__=="__main__":
    unittest.main()
