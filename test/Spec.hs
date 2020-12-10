{-# LANGUAGE OverloadedStrings #-}


import Test.Hspec
import Scanner.Nmap

main :: IO ()
main = hspec $ do
    describe "StateValue" $ do
        it "is open readable" $ do
            (read "open" :: StateValue) `shouldBe` Open

        it "is unfiltered readable" $ do
            (read "unfiltered" :: StateValue) `shouldBe` Unfiltered

        it "is filtered readable" $ do
            (read "filtered" :: StateValue) `shouldBe` Filtered

        it "is open|filtered readable" $ do
            (read "open|filtered" :: StateValue) `shouldBe` OpenFiltered

        it "is closed|filtered readable" $ do
            (read "closed|filtered" :: StateValue) `shouldBe` ClosedFiltered

        it "is closed readable" $ do
            (read "closed" :: StateValue) `shouldBe` Closed

        it "has correct ordinal" $ do
            Open > Unfiltered `shouldBe` True
            Unfiltered > Filtered `shouldBe` True
            Filtered > OpenFiltered `shouldBe` True
            OpenFiltered > ClosedFiltered `shouldBe` True
            ClosedFiltered > Closed `shouldBe` True

    describe "State" $ do
        it "combines states open and closed" $ do
            State Open "syn-ack" <> State Closed "" `shouldBe` State Open "syn-ack"

        it "combines states unfiltered and closed|filtered" $ do
            State Unfiltered "syn-ack" <> State ClosedFiltered "syn-ack2" `shouldBe` State Unfiltered "syn-ack"


    describe "Service" $ do
        it "combines but prefers probed" $ do
            let a = Service "sentinal" "probed" "" "" ""
            let b = Service "sentinal2" "table" "" "" ""
            a <> b `shouldBe` Service "sentinal" "probed" "" "" ""

        it "combines but prefers a product" $ do
            let a = Service "sentinal" "table" "a" "" ""
            let b = Service "sentinal2" "table" "" "" ""
            a <> b `shouldBe` Service "sentinal" "table" "a" "" ""

        it "combines but prefers a version" $ do
            let a = Service "sentinal" "table" "" "a" ""
            let b = Service "sentinal2" "table" "" "" ""
            a <> b `shouldBe` Service "sentinal" "table" "" "a" ""

        it "combines but prefers an osType" $ do
            let a = Service "sentinal" "table" "" "" "a"
            let b = Service "sentinal2" "table" "" "" ""
            a <> b `shouldBe` Service "sentinal" "table" "" "" "a"

    describe "Script" $ do
        it "combines but prefers a value" $ do
            let a = Script "sentinal" "sentinal1"
            let b = Script "" ""
            a <> b `shouldBe` Script "sentinal" "sentinal1"

    describe "Scripts" $ do
        it "merges scripts" $ do
            let a = Scripts [Script "a1" "vb11", Script "a2" "va2"]
            let b = Scripts [Script "b1" "vb1", Script "a1" "vb2"]
            a <> b `shouldBe` Scripts [Script "a1" "vb11", Script "a2" "va2", Script "b1" "vb1"]

    describe "Port" $ do
        it "creates a port id" $ do
            (portId $ Port 21 "tcp" mempty mempty mempty) `shouldBe` "21/tcp"
