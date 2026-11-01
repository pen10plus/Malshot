rule Default_Heuristic {
    strings:
        $s1 = "MALSHOT_TEST"
    condition:
        $s1
}
