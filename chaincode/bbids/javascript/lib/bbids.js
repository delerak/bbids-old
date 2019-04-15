/*
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const { Contract } = require('fabric-contract-api');

class bbids extends Contract {

    async initLedger(ctx) {
        console.info('============= START : Initialize Ledger ===========');
        const rules = [
            {
                RuleAction: 'alert',
                protocol: 'tcp',
                sourceIP: '$HOME_NET',
                sourcePort: '2589',
                Direction: '->',
                destIP: '$EXTERNAL_NET',
                destPort: 'any',
                msg: 'MALWARE-BACKDOOR - Dagger_1.4.0"; flow:to_client,established; content:"2|00 00 00 06 00 00 00|Drives|24 00|",depth 16',
                sid: '105',
                Revision: '14',
                ClassType: 'misc-activity',
                Reference: 'ruleset_community',
                RuleOwner: '',

            },
            {
              RuleAction: 'alert',
              protocol: 'tcp',
              sourceIP: '$EXTERNAL_NET',
              sourcePort: 'any',
              Direction: '->',
              destIP: '$HOME_NET',
              destPort: '7597',
              msg: 'MALWARE-BACKDOOR QAZ Worm Client Login access"; flow:to_server,established; content:"qazwsx.hsq"',
              sid: '108',
              Revision: '11',
              ClassType: 'misc-activity',
              Reference: 'ruleset_community',
              RuleOwner: 'mcafee,98775',
            },
        ];

        for (let i = 0; i < rules.length; i++) {
            rules[i].docType = 'rules';
            await ctx.stub.putState('RULES' + i, Buffer.from(JSON.stringify(rules[i])));
            console.info('Added <--> ', rules[i]);
        }
        console.info('============= END : Initialize Ledger ===========');
    }

    async queryRule(ctx, ruleNumber) {
        const ruleAsBytes = await ctx.stub.getState(ruleNumber); // get the rule from chaincode state
        if (!ruleAsBytes || ruleAsBytes.length === 0) {
            throw new Error(`${ruleNumber} does not exist`);
        }
        console.log(ruleAsBytes.toString());
        return ruleAsBytes.toString();
    }

    async createRule(ctx, ruleNumber, RuleAction, protocol, sourceIP, sourcePort, Direction, destIP, destPort, msg
sid, Revision, ClassType, Reference, RuleOwner) {
        console.info('============= START : Create Rule ===========');

        const rule = {
            RuleAction,
            docType: 'rule',
            protocol,
            sourceIP,
            sourcePort,
            Direction,
            destIP,
            destPort,
            msg,
            sid,
            Revision,
            ClassType,
            Reference,
            RuleOwner,
        };

        await ctx.stub.putState(ruleNumber, Buffer.from(JSON.stringify(rule)));
        console.info('============= END : Create Rule ===========');
    }

    async queryallRules(ctx) {
        const startKey = 'RULE0';
        const endKey = 'RULE9999';

        const iterator = await ctx.stub.getStateByRange(startKey, endKey);

        const allResults = [];
        while (true) {
            const res = await iterator.next();

            if (res.value && res.value.value.toString()) {
                console.log(res.value.value.toString('utf8'));

                const Key = res.value.key;
                let Record;
                try {
                    Record = JSON.parse(res.value.value.toString('utf8'));
                } catch (err) {
                    console.log(err);
                    Record = res.value.value.toString('utf8');
                }
                allResults.push({ Key, Record });
            }
            if (res.done) {
                console.log('end of data');
                await iterator.close();
                console.info(allResults);
                return JSON.stringify(allResults);
            }
        }
    }

    async changeRuleOwner(ctx, ruleNumber, newOwner) {
        console.info('============= START : changeRuleOwner ===========');

        const ruleAsBytes = await ctx.stub.getState(ruleNumber); // get the rule from chaincode state
        if (!ruleAsBytes || ruleAsBytes.length === 0) {
            throw new Error(`${ruleNumber} does not exist`);
        }
        const rule = JSON.parse(ruleAsBytes.toString());
        rule.ruleOwner = newOwner;

        await ctx.stub.putState(ruleNumber, Buffer.from(JSON.stringify(rule)));
        console.info('============= END : changeRuleOwner ===========');
    }

}

module.exports = bbids;
