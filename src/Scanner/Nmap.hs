{-# LANGUAGE Arrows, NoMonomorphismRestriction, OverloadedStrings #-}

module Scanner.Nmap where

import Data.IP hiding (addr)
import Data.Sort
import Prelude hiding (id)
import Data.List
import qualified Data.Map as M
import Data.Tree.NTree.TypeDefs
import Text.XML.HXT.Core hiding (trace)
import Text.HTMLEntity (decode')
import qualified Data.Text as T
import Text.Printf

-- Scan
data ScanResult = ScanResult [Host]

instance Semigroup ScanResult where
    (<>) (ScanResult xs) (ScanResult ys) = do
        let (ScanResult zs) = merge ScanResult hostId xs ys
        ScanResult $ sortBy (\x y -> compare (addr x) (addr y)) zs

instance Show ScanResult where
    show (ScanResult xs) = concat $ map show xs

instance Monoid ScanResult where
    mempty = ScanResult []

hosts (ScanResult x) = x

parseScan = atTag "nmaprun" >>>
    proc x -> do
        hosts <- listA parseHost -< x
        returnA -< hosts

-- Host
data Host = Host {addr :: IP, addrType, hostState :: String, ports :: Ports, hostScripts :: Scripts}

instance Semigroup Host where
    (<>) (Host a b c x hs) (Host _ _ _ x' hs') = Host a b c (x<>x') (hs<>hs')

instance Show Host where
    show (Host a t s ps hs) = concat $ intersperse " " [(show a), s, (show ps)++(hsfmt $ show hs), "\n"]
        where hsfmt x = if x == "" then "" else x++"\n"

parseHS' = atTag "hostscript" >>>
    proc x -> do
        ss <- parseScripts -< x
        returnA -< ss

parseHS = (atTag "hostscript" >>> parseHS') `orElse` (constA [])

parseHost = atTag "host" >>>
    proc x -> do
        status <- atTag "status" -< x
        state <- getAttrValue "state" -< status
        address <- atTag "address" -< x
        addr <- getAttrValue "addr" -< address
        addrType <- getAttrValue "addrtype" -< address
        ports' <- parsePorts -< x
        hs <- parseHS -< x
        returnA -< Host
            {hostState = state
            , addr = read addr :: IP
            , addrType = addrType
            , ports = Ports ports'
            , hostScripts = Scripts hs}

hostId :: Host -> IP
hostId = addr

-- OS Match
data OSMatch = OSMatch {fingerprint :: String, matches :: [String]}

instance Semigroup OSMatch where
    (<>) (OSMatch fp m) (OSMatch fp' m') = OSMatch (if length fp > length fp' then fp else fp') (nub (m++m'))

parseOSMatch = atTag "os" >>>
    proc x -> do
        match <- atTag "osmatch" -< x
        name <- atTag "name" -< match
        fp <- atTag "osmatch" -< x
        fingerprint <- getAttrValue "fingerprint" -< fp
        returnA -< OSMatch fingerprint [""]


-- Port
data Port = Port Int String State Service Scripts deriving (Eq)

instance Semigroup Port where
    (<>) (Port po pr st se sc) (Port _ _ st' se' sc') =
        Port po pr (st <> st') (se <> se') (sc <> sc')

instance Show Port where
    show (Port i r st se sc) = printf "%s/%s %s %s%s" (show i) r (show st) (show se) (scfmt $ show sc)
        where scfmt x = if x == "" then "" else "\n"++x

instance Monoid Port where
    mempty = Port 0 "" mempty mempty mempty

parsePort :: ArrowXml cat => cat (NTree XNode) Port
parsePort = atTag "ports" >>>
    proc x -> do
        port <- atTag "port" -< x
        portID <- getAttrValue "portid" -< port
        protocol <- getAttrValue "protocol" -< port
        service <- parseService -< port
        state_ <- parseState -< port
        scripts <- parseScripts -< port
        returnA -< Port (read portID) protocol state_ service (Scripts $ removeEmpty id scripts)
            where removeEmpty f = filter (\x -> f x /= "")

portId :: Port -> String
portId (Port port protocol _ _ _) = printf "%d/%s" port protocol


data Ports = Ports [Port]

instance Semigroup Ports where
    (<>) (Ports xs) (Ports ys) = do
        let (Ports zs) = merge Ports portId xs ys
        Ports $ sortBy (\(Port x _ _ _ _) (Port y _ _ _ _) -> compare x y) zs

instance Show Ports where
    show (Ports xs) = concat $ ["\n"]++map (\x -> show x ++ "\n") xs


parsePorts :: ArrowXml a => a (NTree XNode) [Port]
parsePorts = listA parsePort


-- StateValue
data StateValue = Closed | ClosedFiltered | OpenFiltered | Filtered | Unfiltered | Open deriving (Eq, Ord)

instance Show StateValue where
    show Open = "open"
    show Unfiltered = "unfiltered"
    show Filtered = "filtered"
    show OpenFiltered = "open|filtered"
    show ClosedFiltered = "closed|filtered"
    show Closed = "closed"

instance Read StateValue where
    readsPrec _ value = 
        tryParse [("open|filtered", OpenFiltered), ("open", Open), ("unfiltered", Unfiltered), ("filtered", Filtered), ("closed|filtered", ClosedFiltered), ("closed", Closed)]
        where tryParse [] = []
              tryParse ((attempt, result):xs) =
                      if (take (length attempt) value) == attempt
                         then [(result, drop (length attempt) value)]
                         else tryParse xs


-- State
data State = State {state :: StateValue, reason :: String} deriving (Eq)

instance Semigroup State where
    (<>) a@(State a' _) b@(State b' _) = if a' >= b' then a else b

instance Monoid State where
    mempty = State Closed ""

instance Show State where
    show (State s r) = (show s) ++ " (" ++r++")"

parseState :: ArrowXml cat => cat (NTree XNode) State
parseState = atTag "state" >>>
    proc service -> do
        state_ <- getAttrValue "state" -< service
        reason_ <- getAttrValue "reason" -< service
        returnA -< State (read state_) reason_

-- Service
data Service = Service {name, method, product, version, osType :: String} deriving (Eq)

instance Semigroup Service where
    (<>) a (Service _ "" _ _ _) = a
    (<>) (Service _ "" _ _ _) b = b
    (<>) (Service _ "table" _ _ _) b@(Service _ "probed" _ _ _ ) = b
    (<>) a@(Service _ "probed" _ _ _) (Service _ "table" _ _ _ ) = a
    (<>) a (Service _ _ _ "" _) = a
    (<>) (Service _ _ "" _ _) b = b
    (<>) a (Service _ _ "" _ _) = a
    (<>) (Service _ _ _ "" _) b = b
    (<>) a (Service _ _ _ _ "") = a
    (<>) (Service _ _ _ _ "") b = b
    (<>) _ b = b

instance Monoid Service where
    mempty = Service "" "" "" "" ""

instance Show Service where
    show (Service n _ "" "" "") = n
    show (Service n _ p "" "") = n++"\nProduct: "++p
    show (Service n _ "" v "") = n++"\nVersion: "++v
    show (Service n _ "" "" o) = n++"\nOS Type: "++o
    show (Service n _ "" v o) = n++"\nVersion: "++v++", OS Type: "++o
    show (Service n _ p "" o) = n++"\nProduct: "++p++", Version: "++o
    show (Service n _ p v "") = n++"\nProduct: "++p++", Version: "++v
    show (Service n _ p v o) = printf "%s\nProduct: %s, Version: %s, OS Type: %s" n p v o

parseService :: ArrowXml cat => cat (NTree XNode) Service
parseService = atTag "service" >>>
    proc service -> do
        serviceName <- getAttrValue "name" -< service
        serviceMethod <- getAttrValue "method" -< service
        product' <- getAttrValue "product" -< service
        version' <- getAttrValue "version" -< service
        osType' <- getAttrValue "ostype" -< service
        returnA -< Service serviceName serviceMethod product' version' osType'

-- Scripts
data Script = Script {id :: String, output :: T.Text}

instance Eq Script where
    (==) a b = id a == id b

instance Monoid Script where
    mempty = Script "" ""

-- Assume id is the same since Scripts will merge by ID
instance Semigroup Script where
    (<>) (Script id output) (Script _ output') =
        if (T.length output) > (T.length output')
           then Script id output
           else Script id output'

instance Show Script where
    show (Script id output) = id++"\n"++(addToFront "\t" (T.unpack output))

parseScript :: ArrowXml cat => cat (NTree XNode) Script
parseScript = atTag "script" >>>
    proc script -> do
        scriptID <- getAttrValue "id" -< script
        output' <- getAttrValue "output" -< script
        returnA -< Script scriptID (T.strip $ T.pack output')

data Scripts = Scripts [Script] deriving (Eq)

instance Semigroup Scripts where
    (<>) (Scripts xs) (Scripts ys) = merge Scripts id xs ys

instance Show Scripts where
    show (Scripts []) = ""
    show (Scripts xs) = (addToFront "|  " $ intercalate "\n" (map (\x -> (show x)) xs))

instance Monoid Scripts where
    mempty = Scripts []

parseScripts :: ArrowXml a => a (NTree XNode) [Script]
parseScripts = listA parseScript

-- utils
addToFront :: String -> String -> String
addToFront x ys = x++atf x ys
    where 
        atf :: String -> String -> String
        atf x ('\n':ys) = "\n"++x++(atf x ys)
        atf x (y:ys) = [y] ++ (atf x ys)
        atf _ "" = ""

parseXML :: String -> IOStateArrow s b XmlTree
parseXML = readDocument [ withValidate no
                        , withRemoveWS yes
                        , withParseHTML yes
                        , withWarnings no
                        ]

atTag :: ArrowXml a => String -> a (NTree XNode) XmlTree
atTag tag = deep $ isElem >>> hasName tag

merge :: (Semigroup a, Ord k) => ([a] -> t) -> (a -> k) -> [a] -> [a] -> t
merge a f xs ys =
    a $ M.elems $ M.unionWith (<>) (conv xs) (conv ys)
        where conv zs = M.fromList $ map (\x -> (f x, x)) zs

-- main
parse x = do
    hosts <- runX $ parseXML x >>> parseScan
    if length hosts == 1
       then return $ ScanResult $ hosts !! 0
       else return $ ScanResult []
