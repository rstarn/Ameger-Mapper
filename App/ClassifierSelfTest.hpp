#pragma once

/*
 * Classifier self-test.
 *
 * Its own translation unit so a test binary can run it without linking the
 * mapper's entry point and inheriting its requireAdministrator manifest.
 * Mapper.exe reaches it through --self-test-classifier; TestClassifier.exe
 * calls it as its whole wmain.
 */

/*
 * Builds synthetic PE images in memory and checks the four classification
 * cases. Returns 0 when all pass, non-zero on failure.
 */
int RunClassifierSelfTest();
