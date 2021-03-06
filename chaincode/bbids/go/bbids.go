/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright SourcePortship.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * The sample smart contract for documentation topic:
 * Writing Your First Blockchain Application
 */

package main

/* Imports
 * 4 utility libraries for formatting, handling bytes, reading and writing JSON, and string manipulation
 * 2 specific Hyperledger Fabric specific libraries for Smart Contracts
 */
import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	sc "github.com/hyperledger/fabric/protos/peer"
)

// Define the Smart Contract structure
type SmartContract struct {
}

// Define the rule structure, with properties.  Structure tags are used by encoding/json library
type Rule struct {
	RuleAction   string `json:"ruleaction"`
	Protocol  string `json:"protocol"`
	SourceIP string `json:"sourceip"`
	SourcePort  string `json:"sourceport"`
}

/*
 * The Init method is called when the Smart Contract "fabRule" is instantiated by the blockchain network
 * Best practice is to have any Ledger initialization in separate function -- see initLedger()
 */
func (s *SmartContract) Init(APIstub shim.ChaincodeStubInterface) sc.Response {
	return shim.Success(nil)
}
docker rmi $(docker images -q)
/*
 * The Invoke method is called as a result of an application request to run the Smart Contract "fabRule"
 * The calling application program has also specified the particular smart contract function to be called, with arguments
 */
func (s *SmartContract) Invoke(APIstub shim.ChaincodeStubInterface) sc.Response {

	// Retrieve the requested Smart Contract function and arguments
	function, args := APIstub.GetFunctionAndParameters()
	// Route to the appropriate handler function to interact with the ledger appropriately
	if function == "queryRule" {
		return s.queryRule(APIstub, args)
	} else if function == "initLedger" {
		return s.initLedger(APIstub)
	} else if function == "createRule" {
		return s.createRule(APIstub, args)
	} else if function == "queryAllRules" {
		return s.queryAllRules(APIstub)
	} else if function == "changeRuleSourcePort" {
		return s.changeRuleSourcePort(APIstub, args)
	}

	return shim.Error("Invalid Smart Contract function name.")
}

func (s *SmartContract) queryRule(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	RuleAsBytes, _ := APIstub.GetState(args[0])
	return shim.Success(RuleAsBytes)
}

func (s *SmartContract) initLedger(APIstub shim.ChaincodeStubInterface) sc.Response {
	Rules := []Rule{
		Rule{RuleAction: "alert", Protocol: "tcp", SourceIP: "$HOME_NET", SourcePort: "2589"},
		Rule{RuleAction: "alert", Protocol: "tcp", SourceIP: "$HOME_NET", SourcePort: "any"},
		Rule{RuleAction: "alert", Protocol: "tcp", SourceIP: "$HOME_NET", SourcePort: "any"},
		Rule{RuleAction: "alert", Protocol: "tcp", SourceIP: "$HOME_NET", SourcePort: "any"},
		Rule{RuleAction: "alert", Protocol: "tcp", SourceIP: "$HOME_NET", SourcePort: "any"},
		Rule{RuleAction: "alert", Protocol: "tcp", SourceIP: "$HOME_NET", SourcePort: "any"},
		Rule{RuleAction: "alert", Protocol: "tcp", SourceIP: "$HOME_NET", SourcePort: "any"},
		Rule{RuleAction: "alert", Protocol: "tcp", SourceIP: "$HOME_NET", SourcePort: "any"},
		Rule{RuleAction: "alert", Protocol: "tcp", SourceIP: "$HOME_NET", SourcePort: "any"},
		Rule{RuleAction: "alert", Protocol: "tcp", SourceIP: "$HOME_NET", SourcePort: "any"},
	}

	i := 0
	for i < len(Rules) {
		fmt.Println("i is ", i)
		RuleAsBytes, _ := json.Marshal(Rules[i])
		APIstub.PutState("Rule"+strconv.Itoa(i), RuleAsBytes)
		fmt.Println("Added", Rules[i])
		i = i + 1
	}

	return shim.Success(nil)
}

func (s *SmartContract) createRule(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 5 {
		return shim.Error("Incorrect number of arguments. Expecting 5")
	}

	var Rule = Rule{RuleAction: args[1], Protocol: args[2], SourceIP: args[3], SourcePort: args[4]}

	RuleAsBytes, _ := json.Marshal(Rule)
	APIstub.PutState(args[0], RuleAsBytes)

	return shim.Success(nil)
}

func (s *SmartContract) queryAllRules(APIstub shim.ChaincodeStubInterface) sc.Response {

	startKey := "Rule0"
	endKey := "Rule999"

	resultsIterator, err := APIstub.GetStateByRange(startKey, endKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	defer resultsIterator.Close()

	// buffer is a JSON array containing QueryResults
	var buffer bytes.Buffer
	buffer.WriteString("[")

	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return shim.Error(err.Error())
		}
		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		buffer.WriteString("{\"Key\":")
		buffer.WriteString("\"")
		buffer.WriteString(queryResponse.Key)
		buffer.WriteString("\"")

		buffer.WriteString(", \"Record\":")
		// Record is a JSON object, so we write as-is
		buffer.WriteString(string(queryResponse.Value))
		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")

	fmt.Printf("- queryAllRules:\n%s\n", buffer.String())

	return shim.Success(buffer.Bytes())
}

func (s *SmartContract) changeRuleSourcePort(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}

	RuleAsBytes, _ := APIstub.GetState(args[0])
	Rule := Rule{}

	json.Unmarshal(RuleAsBytes, &Rule)
	Rule.SourcePort = args[1]

	RuleAsBytes, _ = json.Marshal(Rule)
	APIstub.PutState(args[0], RuleAsBytes)

	return shim.Success(nil)
}

// The main function is only relevant in unit test mode. Only included here for completeness.
func main() {

	// Create a new Smart Contract
	err := shim.Start(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating new Smart Contract: %s", err)
	}
}
