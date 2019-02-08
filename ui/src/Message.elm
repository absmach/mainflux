module Message exposing (Model, Msg(..), initial, update, view)

import Bootstrap.Button as Button
import Bootstrap.Form as Form
import Bootstrap.Form.Checkbox as Checkbox
import Bootstrap.Form.Input as Input
import Bootstrap.Grid as Grid
import Bootstrap.Table as Table
import Bootstrap.Utilities.Spacing as Spacing
import Channel
import Error
import Helpers
import Html exposing (..)
import Html.Attributes exposing (..)
import Http
import Thing
import Url.Builder as B


url =
    { base = "http://localhost"
    }


type alias Model =
    { message : String
    , token : String
    , channel : String
    , response : String
    , things : Thing.Model
    , channels : Channel.Model
    }


initial : Model
initial =
    { message = ""
    , token = ""
    , channel = ""
    , response = ""
    , things = Thing.initial
    , channels = Channel.initial
    }


type Msg
    = SubmitMessage String
    | SubmitToken String
    | SubmitChannel String
    | SendMessage
    | SentMessage (Result Http.Error Int)
    | ThingMsg Thing.Msg
    | ChannelMsg Channel.Msg


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        SubmitMessage message ->
            ( { model | message = message }, Cmd.none )

        SubmitChannel channel ->
            ( { model | channel = channel }, Cmd.none )

        SubmitToken token ->
            ( { model | token = token }, Cmd.none )

        SendMessage ->
            ( model
            , Http.request
                { method = "POST"
                , headers = [ Http.header "Authorization" model.token ]
                , url = B.crossOrigin url.base [ "http", "channels", model.channel, "messages" ] []
                , body = Http.stringBody "application/json" model.message
                , expect = expectMessage SentMessage
                , timeout = Nothing
                , tracker = Nothing
                }
            )

        SentMessage result ->
            case result of
                Ok statusCode ->
                    ( { model | response = "Ok " ++ String.fromInt statusCode }, Cmd.none )

                Err error ->
                    ( { model | response = Error.handle error }, Cmd.none )

        ThingMsg subMsg ->
            let
                ( updatedThing, thingCmd ) =
                    Thing.update subMsg model.things token
            in
            ( { model | things = updatedThing }, Cmd.map ThingMsg thingCmd )

        ChannelMsg subMsg ->
            let
                ( updatedChannel, channelCmd ) =
                    Channel.update subMsg model.channels token
            in
            ( { model | channels = updatedChannel }, Cmd.map ChannelMsg channelCmd )


view : Model -> Html Msg
view model =
    Grid.container []
        [ Grid.row []
            [ Grid.col []
                [ Form.form []
                    [ Form.group []
                        [ Form.label [ for "chan" ] [ text "Channel id" ]
                        , Input.email [ Input.id "chan", Input.onInput SubmitChannel ]
                        ]
                    , Form.group []
                        [ Form.label [ for "token" ] [ text "Thing token" ]
                        , Input.text [ Input.id "token", Input.onInput SubmitToken ]
                        ]
                    , Form.group []
                        [ Form.label [ for "message" ] [ text "Message" ]
                        , Input.text [ Input.id "message", Input.onInput SubmitMessage ]
                        ]
                    , Button.button [ Button.primary, Button.attrs [ Spacing.ml1 ], Button.onClick SendMessage ] [ text "Send" ]
                    ]
                ]
            ]
        , Grid.row []
            [ Grid.col []
                [ Html.map ThingMsg
                    (Grid.row []
                        [ Grid.col [] [ Input.text [ Input.placeholder "offset", Input.id "offset", Input.onInput Thing.SubmitOffset ] ]
                        , Grid.col [] [ Input.text [ Input.placeholder "limit", Input.id "limit", Input.onInput Thing.SubmitLimit ] ]
                        ]
                    )
                , Grid.row []
                    [ Grid.col []
                        [ Table.simpleTable
                            ( Table.simpleThead
                                [ Table.th [] [ text "Name" ]
                                , Table.th [] [ text "Id" ]
                                ]
                            , Table.tbody [] (genThingRows model.things.things)
                            )
                        ]
                    ]
                ]
            , Grid.col []
                [ Html.map ChannelMsg
                    (Grid.row []
                        [ Grid.col [] [ Input.text [ Input.placeholder "offset", Input.id "offset", Input.onInput Channel.SubmitOffset ] ]
                        , Grid.col [] [ Input.text [ Input.placeholder "limit", Input.id "limit", Input.onInput Channel.SubmitLimit ] ]
                        ]
                    )
                , Grid.row []
                    [ Grid.col []
                        [ Table.simpleTable
                            ( Table.simpleThead
                                [ Table.th [] [ text "Name" ]
                                , Table.th [] [ text "Id" ]
                                ]
                            , Table.tbody [] (genChannelRows model.channels.channels)
                            )
                        ]
                    ]
                ]
            ]
        , Helpers.response model.response
        ]


genThingRows : List Thing.Thing -> List (Table.Row Msg)
genThingRows things =
    List.map
        (\thing ->
            Table.tr []
                [ Table.td [] [ Checkbox.checkbox [ Checkbox.id thing.id ] (Helpers.parseName thing.name) ]
                , Table.td [] [ text thing.id ]
                ]
        )
        things


genChannelRows : List Channel.Channel -> List (Table.Row Msg)
genChannelRows channels =
    List.map
        (\channel ->
            Table.tr []
                [ Table.td [] [ Checkbox.checkbox [ Checkbox.id channel.id ] (Helpers.parseName channel.name) ]
                , Table.td [] [ text channel.id ]
                ]
        )
        channels


expectMessage : (Result Http.Error Int -> msg) -> Http.Expect msg
expectMessage toMsg =
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
