/*
 * TestClassifier.exe: the classifier self-test as a whole program.
 *
 * Built without Link/UACExecutionLevel, so the manifest is asInvoker and the
 * test can be run from an ordinary shell. Mapper.exe carries the same test
 * behind --self-test-classifier, but its manifest requires elevation.
 */

#include "../../App/ClassifierSelfTest.hpp"

int wmain() {
	return RunClassifierSelfTest();
}
