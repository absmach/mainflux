module Channel exposing (..)

import Http
import Html exposing  (..)
import Html.Attributes exposing (..)
import Json.Encode as E
import Json.Decode as D
import Url.Builder as B

import Bootstrap.Grid as Grid
import Bootstrap.Button as Button
import Bootstrap.Form as Form
import Bootstrap.Form.Input as Input
import Bootstrap.Utilities.Spacing as Spacing

import Error


url =
    { base = "http://localhost"        
    ,path = [ "channels" ]
    }


path =
    { offset = "0"
    , limit = "10"
    }


type alias Model =
    { channel : String
    , token : String
    , offset : String
    , limit : String
    , response : String
    }


initial : Model
initial =
    { channel = ""
    , token = ""
    , offset = path.offset
    , limit = path.limit
    , response = ""
    }


type Msg
    = SubmitChannel String
    | SubmitOffset String
    | SubmitLimit String
    | ProvisionChannel
    | ProvisionedChannel (Result Http.Error Int)
    | RetrieveChannel
    | RetrievedChannel (Result Http.Error (List Channel))
    | RemoveChannel


update : Msg -> Model -> String -> ( Model, Cmd Msg )
update msg model token =
    case msg of
        SubmitChannel channel ->
            ( { model | channel = channel }, Cmd.none )

        SubmitOffset offset ->
            ( { model | offset = offset }, Cmd.none )

        SubmitLimit limit ->
            ( { model | limit = limit }, Cmd.none )

        ProvisionChannel ->
            ( model
            , provision
                (B.crossOrigin url.base url.path [])
                token
                model.channel
            )

        ProvisionedChannel result ->
            case result of
                Ok statusCode ->
                    ( { model | response = "Ok " ++ String.fromInt statusCode }, Cmd.none )

                Err error ->
                    ( { model | response = (Error.handle error) }, Cmd.none )

        RetrieveChannel ->
            ( model
            , retrieve
                (B.crossOrigin url.base url.path (buildQueryParamList model))
                token
            )

        RetrievedChannel result ->
            case result of
                Ok channels ->
                    ( { model | response = channelsToString channels }, Cmd.none )

                Err error ->
                    ( { model | response = (Error.handle error) }, Cmd.none )
            
        RemoveChannel ->
            ( model
            , remove
                (B.crossOrigin url.base (List.append url.path [ model.channel ]) [])
                token
            )            


view : Model -> Html Msg
view model =
    Grid.row []
        [ Grid.col []
          [ Form.form []
            [ Form.group []
              [ Form.label [ for "chan" ] [ text "Name (Provision) or id (Remove)" ]
              , Input.email [ Input.id "chan", Input.onInput SubmitChannel ]
              ]
            , Form.group []
                [ Form.label [ for "offset" ] [ text "Offset" ]
                , Input.text [ Input.id "offset", Input.onInput SubmitOffset ]
                ]
            , Form.group []
                [ Form.label [ for "limit" ] [ text "Limit" ]
                , Input.text [ Input.id "limit", Input.onInput SubmitLimit ]
                ]                
            , Button.button [ Button.primary, Button.attrs [ Spacing.ml1 ], Button.onClick ProvisionChannel ] [ text "Provision" ]
            , Button.button [ Button.primary, Button.attrs [ Spacing.ml1 ], Button.onClick RetrieveChannel ] [ text "Retrieve" ]
            , Button.button [ Button.primary, Button.attrs [ Spacing.ml1 ], Button.onClick RemoveChannel ] [ text "Remove" ]
            ]
          , Html.hr [] []
          , text ("response: " ++ model.response)
          ]
        ]


type alias Channel =
    { name : String
    , id : String
    }


channelDecoder : D.Decoder Channel
channelDecoder =
    D.map2 Channel
        (D.field "name" D.string)
        (D.field "id" D.string)
    

channelListDecoder : D.Decoder (List Channel)
channelListDecoder =
    (D.field "channels" (D.list channelDecoder))


provision : String -> String -> String -> Cmd Msg
provision u token name =
    Http.request
        { method = "POST"
        , headers = [ Http.header "Authorization" token ]
        , url = u
        , body =
            E.object [ ( "name", E.string name ) ]
        |> Http.jsonBody
        , expect = expectProvision ProvisionedChannel
        , timeout = Nothing
        , tracker = Nothing
        }


expectProvision : (Result Http.Error Int -> Msg) -> Http.Expect Msg
expectProvision toMsg =
    Http.expectStringResponse toMsg <|
        \response ->
            case response of
                Http.BadUrl_ u ->
                    Err (Http.BadUrl u)

                Http.Timeout_ ->
                    Err Http.Timeout

                Http.NetworkError_ ->
                    Err Http.NetworkError

                Http.BadStatus_ metadata body ->
                    Err (Http.BadStatus metadata.statusCode)

                Http.GoodStatus_ metadata _ ->
                    Ok metadata.statusCode


retrieve : String -> String -> Cmd Msg
retrieve u token =
    Http.request
        { method = "GET"
        , headers = [ Http.header "Authorization" token ]
        , url = u
        , body = Http.emptyBody
        , expect = expectRetrieve RetrievedChannel
        , timeout = Nothing
        , tracker = Nothing
        }                    


expectRetrieve : (Result Http.Error (List Channel) -> Msg) -> Http.Expect Msg
expectRetrieve toMsg =
  Http.expectStringResponse toMsg <|
    \response ->
      case response of
        Http.BadUrl_ u ->
          Err (Http.BadUrl u)

        Http.Timeout_ ->
          Err Http.Timeout

        Http.NetworkError_ ->
          Err Http.NetworkError

        Http.BadStatus_ metadata body ->
          Err (Http.BadStatus metadata.statusCode)

        Http.GoodStatus_ metadata body ->
          case D.decodeString channelListDecoder body of
            Ok value ->
              Ok value

            Err err ->
              Err (Http.BadBody "Account has no channels")


remove : String -> String -> Cmd Msg
remove u token =
    Http.request
        { method = "DELETE"
        , headers = [ Http.header "Authorization" token ]
        , url = u
        , body = Http.emptyBody
        , expect = expectProvision ProvisionedChannel
        , timeout = Nothing
        , tracker = Nothing
        }


-- HELPERS

                
channelsToString : List Channel -> String
channelsToString channels =
    List.map
        (\channel -> channel.name ++ " " ++ channel.id ++ "; ")
        channels
        |> String.concat


buildQueryParamList : Model -> List B.QueryParameter
buildQueryParamList model =
    List.map 
        (\tpl ->
             case (String.toInt (Tuple.second tpl)) of
                 Just n ->
                     B.int (Tuple.first tpl) n
                            
                 Nothing ->
                     if (Tuple.first tpl) == "offset" then
                         B.string (Tuple.first tpl) path.offset
                     else
                         B.string (Tuple.first tpl) path.limit)
        [("offset", model.offset), ("limit", model.limit)]
