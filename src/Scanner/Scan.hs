module Scanner.Scan where

import Control.Monad
import System.FilePath
import Scanner.Nmap
import System.Process
import Debug.Trace
import System.Random

outdir :: FilePath
outdir = "/" </> "var" </> "nmaplog"

normalScan :: [String]
normalScan = []

agressiveScan :: [String]
agressiveScan = ["-A"]

randFileName :: String -> IO String
randFileName ext = do
    gen <- newStdGen
    let str = take 10 $ randomRs ('a','z') gen 
    return $ str <.> ext

makeScan :: [String] -> [String] -> IO ScanResult
makeScan ips args = do
    filePathName <- randFileName "xml"
    let filePath = outdir </> filePathName
    let args' = ["-oX", filePath] ++ args ++ ips
    out <- readProcess "nmap" args' []
    d <- parse filePath
    return d


makeScans :: [String] -> [[String]] -> IO ScanResult
makeScans ips args = do
    let scans = map (makeScan ips) args
    foldM (fmap . (<>)) mempty scans
