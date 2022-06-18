package ydb

import (
	"context"

	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/table"
	"github.com/ydb-platform/ydb-go-sdk/v3/table/result"
	"github.com/ydb-platform/ydb-go-sdk/v3/table/result/named"
	"github.com/ydb-platform/ydb-go-sdk/v3/table/types"

	"github.com/charCharacter/history/auth/configs"
	"github.com/charCharacter/history/auth/models"
)

type YDB struct {
	ctx  context.Context
	conn ydb.Connection
}

func NewYDB(ctx context.Context, configs *configs.YDB) (*YDB, error) {
	// строка подключения
	dsn := configs.DSNString
	// создаем объект подключения db, является входной точкой для сервисов YDB
	db, err := ydb.Open(
		ctx,
		dsn,
	)
	if err != nil {
		return nil, err
	}
	// закрытие драйвера по окончании работы программы обязательно

	return &YDB{
		ctx:  ctx,
		conn: db,
	}, nil
}

func (c *YDB) Close() error {
	return c.conn.Close(c.ctx)
}

func (c *YDB) UserCreate(u *models.User) (err error) {
	err = c.conn.Table().DoTx( // Do retry operation on errors with best effort
		c.ctx, // context manages exiting from Do
		func(ctx context.Context, tx table.TransactionActor) (err error) { // retry operation
			res, err := tx.Execute(
				ctx, `
					DECLARE $uid AS String;
					DECLARE $username AS String;
					DECLARE $password AS String;
					INSERT INTO  users( uid, username, password)
					VALUES ( $uid, $username, $password);
				`,
				table.NewQueryParameters(
					table.ValueParam("$uid", types.StringValue([]byte(u.UID))),
					table.ValueParam("$username", types.StringValue([]byte(u.Username))),
					table.ValueParam("$password", types.StringValue([]byte(u.HashedPassword))),
				),
			)
			if err != nil {
				return err
			}
			if err = res.Err(); err != nil {
				return err
			}
			return res.Close()
		},
	)
	return
}

func (c *YDB) UserFind(username string) (m models.User, err error) {
	var (
		readTx = table.TxControl(
			table.BeginTx(
				table.WithOnlineReadOnly(),
			),
			table.CommitTx(),
		)
		res         result.Result
		resUid      *string // указатель - для опциональных результатов
		resUsername *string // указатель - для опциональных результатов
		resPassword *string // указатель - для опциональных результатов
	)
	err = c.conn.Table().Do(
		c.ctx,
		func(ctx context.Context, s table.Session) (err error) {
			_, res, err = s.Execute(
				ctx,
				readTx,
				`
        DECLARE $username AS string;
        SELECT uid, username, password
        FROM
          users
        WHERE
          username = $username;
      `,
				table.NewQueryParameters(
					table.ValueParam("$username", types.StringValue([]byte(username))), // подстановка в условие запроса
				),
			)
			if err != nil {
				return err
			}
			defer func() {
				_ = res.Close() // закрытие result'а обязательно
			}()
			for res.NextResultSet(ctx) {
				for res.NextRow() {
					err = res.ScanNamed(
						named.Optional("uid", &resUid),
						named.Optional("username", &resUsername),
						named.Optional("password", &resPassword),
					)
					if err != nil {
						return err
					}
				}
			}
			return res.Err()
		},
	)
	m.UID = *resUid
	m.HashedPassword = *resPassword
	m.Username = *resUsername
	return m, nil
}
