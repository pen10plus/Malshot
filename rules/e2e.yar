rule MalShot_E2E_Sample {
    strings:
        $marker = "MALSHOT-E2E-SAMPLE"
    condition:
        $marker
}
