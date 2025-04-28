//
// Created by machiry on 12/28/16.
//

#include "bug_detectors/BugDetectorDriver.h"
#include "bug_detectors/GlobalVariableRaceDetector.h"
#include "bug_detectors/UAFDetector.h"

using namespace llvm;

namespace DRCHECKER {

//#define DISABLE_GLOBALVARIABLERACEDETECTOR

    void BugDetectorDriver::addUAFBugDetector(GlobalState &targetState,
                                              Function *toAnalyze,
                                              CallContext *ctx,
                                              std::vector<VisitorCallback *> *allCallbacks,
                                              FunctionChecker *targetChecker) {
        VisitorCallback *currDetector = new UAFDetector(targetState, toAnalyze, ctx, targetChecker);
        allCallbacks->push_back(currDetector);
    }

    void BugDetectorDriver::addPreAnalysisBugDetectors(GlobalState &targetState,
                                                       Function *toAnalyze,
                                                       CallContext *ctx,
                                                       std::vector<VisitorCallback *> *allCallbacks,
                                                       FunctionChecker *targetChecker) {

    }

    void BugDetectorDriver::addPostAnalysisBugDetectors(GlobalState &targetState,
                                                        Function *toAnalyze,
                                                        CallContext *ctx,
                                                        std::vector<VisitorCallback *> *allCallbacks,
                                                        FunctionChecker *targetChecker) {
#ifndef DISABLE_GLOBALVARIABLERACEDETECTOR
        VisitorCallback *globalVarRaceDetector = new GlobalVariableRaceDetector(targetState,
                                                                                toAnalyze, ctx,
                                                                                targetChecker);
        allCallbacks->push_back(globalVarRaceDetector);
#endif
    }

    void BugDetectorDriver::printAllWarnings(GlobalState &targetState, llvm::raw_ostream& O) {
        O << "{\"num_contexts\":";
        if(targetState.allVulnWarnings.size() == 0) {
            O << "0";
            //O << "No Warnings. Everything looks good\n";
        } else {
            O << targetState.allVulnWarnings.size() << ",\n";
            bool addout_comma = false;
            O << "\"all_contexts\":[\n";
            for (auto warn_iter = targetState.allVulnWarnings.begin(); warn_iter != targetState.allVulnWarnings.end();
                 warn_iter++) {
                CallContext *targetContext = warn_iter->first;
                std::set<VulnerabilityWarning *> *allWarnings = warn_iter->second;
                if (!targetContext || !allWarnings || !allWarnings->size()) {
                    continue;
                }
                bool addin_comma = false;
                if(addout_comma) {
                    O << ",\n";
                }
                O << "{";
                O << "\"num_warnings\":" << allWarnings->size() << ",\n";
                // O << "At Calling Context:";
                targetContext->printJson(O);
                O << ",";

                //O << "Found:" << allWarnings->size() << " warnings.\n";
                long currWarningNo = 1;
                O << "\"warnings\":[\n";
                for (VulnerabilityWarning *currWarning:*(allWarnings)) {
                    if(addin_comma) {
                        O << ",\n";
                    }
                    O << "{";
                    O << "\"warn_no\":" << currWarningNo << ",";
                    currWarning->printWarning(O);
                    currWarningNo++;
                    addin_comma = true;
                    O << "}";
                }
                O << "\n]";
                addout_comma = true;
                O << "}";
            }
            O << "]\n";
        }
        O << "\n}";
    }

    void BugDetectorDriver::printWarningsByInstr(GlobalState &targetState, llvm::raw_ostream& O) {
        O << "{\"num_instructions\":";
        if(targetState.warningsByInstr.size() == 0) {
            O << "0";
            //O << "No Warnings. Everything looks good\n";
        } else {
            O << targetState.warningsByInstr.size() << ",\n";
            bool addout_comma = false;
            O << "\"all_instrs\":[\n";
            for (auto warn_iter = targetState.warningsByInstr.begin(); warn_iter != targetState.warningsByInstr.end();
                 warn_iter++) {
                Instruction *currInstr = warn_iter->first;
                std::set<VulnerabilityWarning *> *allWarnings = warn_iter->second;
                if (!currInstr || !allWarnings || !allWarnings->size()) {
                    continue;
                }
                bool addin_comma = false;
                if(addout_comma) {
                    O << ",\n";
                }
                O << "{";
                O << "\"num_warnings\":" << allWarnings->size() << ",\n";
                InstructionUtils::printInstJson(currInstr,O);
                long currWarningNo = 1;
                O << ",\"warnings\":[\n";
                for (VulnerabilityWarning *currWarning : *(allWarnings)) {
                    if(addin_comma) {
                        O << ",\n";
                    }
                    O << "{";
                    O << "\"warn_no\":" << currWarningNo << ",";
                    currWarning->printWarning(O);
                    currWarningNo++;
                    addin_comma = true;
                    O << "}";
                }
                O << "\n]";
                addout_comma = true;
                O << "}";
            }
            O << "]\n";
        }
        O << "\n}";
    }
}
