package waf

import "context"

type requestIDKey struct{}

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

func requestID(request interface{ Context() context.Context }) string {
	id, _ := request.Context().Value(requestIDKey{}).(string)
	return id
}
